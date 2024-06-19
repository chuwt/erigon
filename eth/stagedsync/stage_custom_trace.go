package stagedsync

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/holiman/uint256"

	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/datadir"
	"github.com/ledgerwatch/erigon-lib/common/dbg"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon-lib/log/v3"
	state2 "github.com/ledgerwatch/erigon-lib/state"
	"github.com/ledgerwatch/erigon-lib/wrap"
	"github.com/ledgerwatch/erigon/cmd/state/exec3"
	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/eth/ethconfig"
	"github.com/ledgerwatch/erigon/ethdb/prune"
	"github.com/ledgerwatch/erigon/turbo/services"
)

type CustomTraceCfg struct {
	tmpdir   string
	db       kv.RwDB
	prune    prune.Mode
	execArgs *exec3.ExecArgs
}

func StageCustomTraceCfg(db kv.RwDB, prune prune.Mode, dirs datadir.Dirs, br services.FullBlockReader, cc *chain.Config,
	engine consensus.Engine, genesis *types.Genesis, syncCfg *ethconfig.Sync) CustomTraceCfg {
	execArgs := &exec3.ExecArgs{
		ChainDB:     db,
		BlockReader: br,
		Prune:       prune,
		ChainConfig: cc,
		Dirs:        dirs,
		Engine:      engine,
		Genesis:     genesis,
		Workers:     syncCfg.ExecWorkerCount,
	}
	return CustomTraceCfg{
		db:       db,
		prune:    prune,
		execArgs: execArgs,
	}
}

func SpawnCustomTrace(s *StageState, txc wrap.TxContainer, cfg CustomTraceCfg, ctx context.Context, prematureEndBlock uint64, logger log.Logger) error {
	useExternalTx := txc.Ttx != nil
	var tx kv.TemporalRwTx
	if !useExternalTx {
		_tx, err := cfg.db.BeginRw(ctx)
		if err != nil {
			return err
		}
		defer _tx.Rollback()
		tx = _tx.(kv.TemporalRwTx)
	} else {
		tx = txc.Ttx.(kv.TemporalRwTx)
	}

	endBlock, err := s.ExecutionAt(tx)
	if err != nil {
		return fmt.Errorf("getting last executed block: %w", err)
	}
	if s.BlockNumber > endBlock { // Erigon will self-heal (download missed blocks) eventually
		return nil
	}
	// if prematureEndBlock is nonzero and less than the latest executed block,
	// then we only run the log index stage until prematureEndBlock
	if prematureEndBlock != 0 && prematureEndBlock < endBlock {
		endBlock = prematureEndBlock
	}
	// It is possible that prematureEndBlock < s.BlockNumber,
	// in which case it is important that we skip this stage,
	// or else we could overwrite stage_at with prematureEndBlock
	if endBlock <= s.BlockNumber {
		return nil
	}

	startBlock := s.BlockNumber
	if startBlock > 0 {
		startBlock++
	}

	logEvery := time.NewTicker(10 * time.Second)
	defer logEvery.Stop()
	var m runtime.MemStats
	var prevBlockNumLog uint64 = startBlock

	keyTotal := []byte("total")
	total, err := lastGasUsed(tx, keyTotal)
	if err != nil {
		return err
	}

	doms, err := state2.NewSharedDomains(tx, logger)
	if err != nil {
		return err
	}
	defer doms.Close()

	fmt.Printf("dbg1: %s\n", tx.ViewID())
	//TODO: new tracer may get tracer from pool, maybe add it to TxTask field
	/// maybe need startTxNum/endTxNum
	if err = exec3.CustomTraceMapReduce(startBlock, endBlock, exec3.TraceConsumer{
		NewTracer: func() exec3.GenericTracer { return nil },
		Reduce: func(txTask *state.TxTask, tx kv.Tx) error {
			if txTask.Error != nil {
				return err
			}

			total.AddUint64(total, txTask.UsedGas)
			v := total.Bytes()

			doms.SetTx(tx)
			doms.SetTxNum(txTask.TxNum)
			err = doms.DomainPut(kv.GasUsedDomain, keyTotal, nil, v, nil, 0)
			if err != nil {
				return err
			}

			select {
			case <-logEvery.C:
				dbg.ReadMemStats(&m)
				log.Info("Scanned", "block", txTask.BlockNum, "blk/sec", float64(txTask.BlockNum-prevBlockNumLog)/10, "alloc", libcommon.ByteCount(m.Alloc), "sys", libcommon.ByteCount(m.Sys))
				prevBlockNumLog = txTask.BlockNum
			default:
			}

			return nil
		},
	}, ctx, tx, cfg.execArgs, logger); err != nil {
		return err
	}
	if err = s.Update(tx.(kv.RwTx), endBlock); err != nil {
		return err
	}

	if err := doms.Flush(ctx, tx); err != nil {
		return err
	}

	if !useExternalTx {
		if err = tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

func lastGasUsed(tx kv.TemporalTx, key []byte) (*uint256.Int, error) {
	total := uint256.NewInt(0)
	v, _, err := tx.DomainGet(kv.GasUsedDomain, key, nil)
	if err != nil {
		return nil, err
	}
	if len(v) > 0 {
		total.SetBytes(v)
	}
	return total, nil

	/*
		it, err := tx.IndexRange(kv.GasUsedHistoryIdx, key, -1, -1, order.Desc, 1)
		if err != nil {
			return nil, err
		}
		defer it.Close()
		if it.HasNext() {
			lastTxNum, err := it.Next()
			if err != nil {
				return nil, err
			}
			lastTotal, ok, err := tx.HistoryGet(kv.GasUsedHistory, key, lastTxNum)
			if err != nil {
				return nil, err
			}
			if ok {
				total.SetBytes(lastTotal)
			}
		}
		return total, nil
	*/
}

func UnwindCustomTrace(u *UnwindState, s *StageState, txc wrap.TxContainer, cfg CustomTraceCfg, ctx context.Context, logger log.Logger) (err error) {
	useExternalTx := txc.Ttx != nil
	var tx kv.TemporalTx
	if !useExternalTx {
		_tx, err := cfg.db.BeginRw(ctx)
		if err != nil {
			return err
		}
		defer _tx.Rollback()
		tx = _tx.(kv.TemporalTx)
	} else {
		tx = txc.Ttx
	}

	if err := u.Done(tx.(kv.RwTx)); err != nil {
		return fmt.Errorf("%w", err)
	}
	if !useExternalTx {
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func PruneCustomTrace(s *PruneState, tx kv.RwTx, cfg CustomTraceCfg, ctx context.Context, logger log.Logger) (err error) {
	return nil
}
