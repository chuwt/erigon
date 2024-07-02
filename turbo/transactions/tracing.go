package transactions

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"math/big"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/ledgerwatch/log/v3"

	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
	"github.com/ledgerwatch/erigon/eth/stagedsync"
	"github.com/ledgerwatch/erigon/eth/tracers"
	"github.com/ledgerwatch/erigon/eth/tracers/logger"
	"github.com/ledgerwatch/erigon/turbo/rpchelper"
	"github.com/ledgerwatch/erigon/turbo/services"
)

type BlockGetter interface {
	// GetBlockByHash retrieves a block from the database by hash, caching it if found.
	GetBlockByHash(hash libcommon.Hash) (*types.Block, error)
	// GetBlock retrieves a block from the database by hash and number,
	// caching it if found.
	GetBlock(hash libcommon.Hash, number uint64) *types.Block
}

// ComputeTxEnv returns the execution environment of a certain transaction.
func ComputeTxEnv(ctx context.Context, engine consensus.EngineReader, block *types.Block, cfg *chain.Config, headerReader services.HeaderReader, dbtx kv.Tx, txIndex int, historyV3 bool) (core.Message, evmtypes.BlockContext, evmtypes.TxContext, *state.IntraBlockState, state.StateReader, error) {
	reader, err := rpchelper.CreateHistoryStateReader(dbtx, block.NumberU64(), txIndex, historyV3, cfg.ChainName)
	if err != nil {
		return nil, evmtypes.BlockContext{}, evmtypes.TxContext{}, nil, nil, err
	}

	// Create the parent state database
	statedb := state.New(reader)

	if txIndex == 0 && len(block.Transactions()) == 0 {
		return nil, evmtypes.BlockContext{}, evmtypes.TxContext{}, statedb, reader, nil
	}
	getHeader := func(hash libcommon.Hash, n uint64) *types.Header {
		h, _ := headerReader.HeaderByNumber(ctx, dbtx, n)
		return h
	}
	header := block.HeaderNoCopy()

	blockContext := core.NewEVMBlockContext(header, core.GetHashFn(header, getHeader), engine, nil)

	// Recompute transactions up to the target index.
	signer := types.MakeSigner(cfg, block.NumberU64(), block.Time())
	if historyV3 {
		rules := cfg.Rules(blockContext.BlockNumber, blockContext.Time)
		txn := block.Transactions()[txIndex]
		statedb.SetTxContext(txn.Hash(), block.Hash(), txIndex)
		msg, _ := txn.AsMessage(*signer, block.BaseFee(), rules)
		if msg.FeeCap().IsZero() && engine != nil {
			syscall := func(contract libcommon.Address, data []byte) ([]byte, error) {
				return core.SysCallContract(contract, data, cfg, statedb, header, engine, true /* constCall */)
			}
			msg.SetIsFree(engine.IsServiceTransaction(msg.From(), syscall))
		}

		TxContext := core.NewEVMTxContext(msg)
		return msg, blockContext, TxContext, statedb, reader, nil
	}
	vmenv := vm.NewEVM(blockContext, evmtypes.TxContext{}, statedb, cfg, vm.Config{})
	rules := vmenv.ChainRules()

	consensusHeaderReader := stagedsync.NewChainReaderImpl(cfg, dbtx, nil, nil)

	logger := log.New("tracing")
	err = core.InitializeBlockExecution(engine.(consensus.Engine), consensusHeaderReader, header, cfg, statedb, logger)
	if err != nil {
		return nil, evmtypes.BlockContext{}, evmtypes.TxContext{}, nil, nil, err
	}

	for idx, txn := range block.Transactions() {
		select {
		default:
		case <-ctx.Done():
			return nil, evmtypes.BlockContext{}, evmtypes.TxContext{}, nil, nil, ctx.Err()
		}
		statedb.SetTxContext(txn.Hash(), block.Hash(), idx)

		// Assemble the transaction call message and return if the requested offset
		msg, _ := txn.AsMessage(*signer, block.BaseFee(), rules)
		if msg.FeeCap().IsZero() && engine != nil {
			syscall := func(contract libcommon.Address, data []byte) ([]byte, error) {
				return core.SysCallContract(contract, data, cfg, statedb, header, engine, true /* constCall */)
			}
			msg.SetIsFree(engine.IsServiceTransaction(msg.From(), syscall))
		}

		TxContext := core.NewEVMTxContext(msg)
		if idx == txIndex {
			return msg, blockContext, TxContext, statedb, reader, nil
		}
		vmenv.Reset(TxContext, statedb)
		// Not yet the searched for transaction, execute on top of the current state
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(txn.GetGas()).AddBlobGas(txn.GetBlobGas()), true /* refunds */, false /* gasBailout */); err != nil {
			return nil, evmtypes.BlockContext{}, evmtypes.TxContext{}, nil, nil, fmt.Errorf("transaction %x failed: %w", txn.Hash(), err)
		}
		// Ensure any modifications are committed to the state
		// Only delete empty objects if EIP161 (part of Spurious Dragon) is in effect
		_ = statedb.FinalizeTx(rules, reader.(*state.PlainState))

		if idx+1 == len(block.Transactions()) {
			// Return the state from evaluating all txs in the block, note no msg or TxContext in this case
			return nil, blockContext, evmtypes.TxContext{}, statedb, reader, nil
		}
	}
	return nil, evmtypes.BlockContext{}, evmtypes.TxContext{}, nil, nil, fmt.Errorf("transaction index %d out of range for block %x", txIndex, block.Hash())
}

type TokenBalanceTracerResult struct {
	Contracts    map[libcommon.Address][]string          `json:"contracts"`
	TopContracts map[libcommon.Address]libcommon.Address `json:"topContracts"`
}

// TraceTxToken configures a new tracer according to the provided configuration, and
// executes the given message in the provided environment. The return value will
// be tracer dependent.
func TraceTxToken(
	ctx context.Context,
	message core.Message,
	blockCtx evmtypes.BlockContext,
	txCtx evmtypes.TxContext,
	ibs evmtypes.IntraBlockState,
	config *tracers.TraceConfig,
	chainConfig *chain.Config,
	stream *jsoniter.Stream,
	callTimeout time.Duration,
) error {
	tracerString := "tokenBalanceTracer"
	config.Tracer = &tracerString
	tracer, streaming, cancel, err := AssembleTracer(ctx, config, txCtx.TxHash, stream, callTimeout)
	if err != nil {
		stream.WriteNil()
		return err
	}

	defer cancel()

	execCb := func(evm *vm.EVM, refunds bool) (json.RawMessage, error) {
		logger := log.New()
		gp := new(core.GasPool).AddGas(message.Gas()).AddBlobGas(message.BlobGas())
		_, err = core.ApplyMessage(evm, message, gp, refunds, false /* gasBailout */)
		if err != nil {
			return nil, fmt.Errorf("tracing failed: %w", err)
		}
		rawJson, err := tracer.(tracers.Tracer).GetResult()
		if err != nil {
			return nil, fmt.Errorf("get tracing result failed: %w", err)
		}
		logger.Debug("contracts tracing result", "result", string(rawJson))

		contracts := new(TokenBalanceTracerResult)
		if err = json.Unmarshal(rawJson, contracts); err != nil {
			return nil, fmt.Errorf("get tracing unmarshal failed: %w", err)
		}
		// after getting the contract and address
		// next we should check if the contracts are tokens by using balanceOf
		tokenContract := NewTokenContract()
		if err = tokenContract.Override().Override(ibs.(*state.IntraBlockState)); err != nil {
			return nil, fmt.Errorf("override failed: %w", err)
		}
		tokenCheckList := make([]libcommon.Address, 0)
		for key := range contracts.Contracts {
			tokenCheckList = append(tokenCheckList, key)
		}
		data, err := tokenContract.abi.Pack("balance", tokenCheckList)
		if err != nil {
			return nil, fmt.Errorf("gen balance data failed: %w", err)
		}

		rawTokenInfo, _, err := evm.StaticCall(vm.AccountRef(tokenContract.caller), tokenContract.address, data, 50_000_000_000)
		if err != nil {
			return nil, fmt.Errorf("check token failed: %w", err)
		}

		// todo, check if the balanceOf success
		contractResult, err := tokenContract.abi.Unpack("balance", rawTokenInfo)
		if err != nil {
			return nil, fmt.Errorf("call balance data failed: %w", err)
		}

		// get the result of the tracer
		rawJson, err = tracer.(tracers.Tracer).GetResult()
		if err != nil {
			return nil, fmt.Errorf("get tracing result failed: %w", err)
		}
		log.Debug("Balance tracing", "result", string(rawJson))

		balanceCheckContract := new(TokenBalanceTracerResult)
		if err = json.Unmarshal(rawJson, balanceCheckContract); err != nil {
			return nil, fmt.Errorf("get tracing unmarshal failed: %w", err)
		}
		// in order to handle the nonstandard proxy contract (gateway contract + state contract)
		// we set the data to the gateway contract

		// compare the balanceCheckContract to get the tokens
		tokenWithWalletAddress := make(map[libcommon.Address]map[libcommon.Address]struct{})
		for contract, values := range balanceCheckContract.Contracts {
			for _, value := range values {
				stateKeyData, _ := strings.CutPrefix(strings.ToLower(value), "0x")
				containsAddress, _ := strings.CutPrefix(strings.ToLower(tokenContract.address.String()), "0x")

				index := strings.Index(stateKeyData, containsAddress)

				if index != -1 {
					if txKeys, ok := contracts.Contracts[contract]; ok {
						for _, key := range txKeys {
							// compare with the stateKeyData
							key, _ = strings.CutPrefix(strings.ToLower(key), "0x")
							// check if the key == stateKeyData after remove the address data
							if len(key) == len(stateKeyData) && key[:index] == stateKeyData[:index] && key[index+40:] == stateKeyData[index+40:] {
								walletAddress := libcommon.HexToAddress(key[index : index+40])

								// check if the contract has the top contract
								if topContract, ok := balanceCheckContract.TopContracts[contract]; ok {
									if _, has := tokenWithWalletAddress[topContract]; !has {
										tokenWithWalletAddress[topContract] = make(map[libcommon.Address]struct{})
									}
									tokenWithWalletAddress[topContract][walletAddress] = struct{}{}
								}

								if _, has := tokenWithWalletAddress[contract]; !has {
									tokenWithWalletAddress[contract] = make(map[libcommon.Address]struct{})
								}
								tokenWithWalletAddress[contract][walletAddress] = struct{}{}
							}
						}
					}
				}
			}
		}

		// add transfer log
		logs := ibs.(*state.IntraBlockState).GetLogs(txCtx.TxHash)
		logger.Debug("tx logs", "logs", logs)
		for _, transferLog := range logs {
			if len(transferLog.Topics) == 3 && transferLog.Topics[0] == libcommon.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef") {
				if _, has := tokenWithWalletAddress[transferLog.Address]; !has {
					tokenWithWalletAddress[transferLog.Address] = make(map[libcommon.Address]struct{})
				}
				tokenWithWalletAddress[transferLog.Address][libcommon.BytesToAddress(transferLog.Topics[1].Bytes())] = struct{}{}
				tokenWithWalletAddress[transferLog.Address][libcommon.BytesToAddress(transferLog.Topics[2].Bytes())] = struct{}{}
			}
		}
		logger.Debug("token with wallet address", "data", tokenWithWalletAddress)

		// get balances in tokenWithWalletAddress
		tokens := make([]libcommon.Address, 0)
		tokenWallets := make([][]libcommon.Address, 0)
		for token, wallets := range tokenWithWalletAddress {
			tokens = append(tokens, token)
			_wallets := make([]libcommon.Address, 0)
			for wallet := range wallets {
				_wallets = append(_wallets, wallet)
			}
			tokenWallets = append(tokenWallets, _wallets)
		}
		data, err = tokenContract.abi.Pack("tokenBalance", tokens, tokenWallets)
		if err != nil {
			return nil, fmt.Errorf("pack tokenBalance failed: %w", err)
		}
		// get wallet balance
		rawWalletBalance, _, err := evm.StaticCall(vm.AccountRef(tokenContract.caller), tokenContract.address, data, 50_000_000_000)
		if err != nil {
			return nil, fmt.Errorf("check token failed: %w", err)
		}
		contractResult, err = tokenContract.abi.Unpack("tokenBalance", rawWalletBalance)
		if err != nil {
			return nil, fmt.Errorf("call balance data failed: %w", err)
		}
		balances := make([][]*big.Int, 0)

		abi.ConvertType(contractResult[0], &balances)

		balanceResult := make(map[libcommon.Address]map[libcommon.Address]*big.Int)
		for index, tokenAddress := range tokens {
			for balIndex, bal := range balances[index] {
				if _, ok := balanceResult[tokenAddress]; !ok {
					balanceResult[tokenAddress] = make(map[libcommon.Address]*big.Int)
				}
				balanceResult[tokenAddress][tokenWallets[index][balIndex]] = bal
			}
		}
		return json.Marshal(balanceResult)
	}

	evm := vm.NewEVM(blockCtx, txCtx, ibs, chainConfig, vm.Config{Debug: true, Tracer: tracer, NoBaseFee: true})
	result, err := execCb(evm, true)
	if err != nil {
		if streaming {
			stream.WriteArrayEnd()
			stream.WriteObjectEnd()
		} else {
			stream.WriteNil()
		}
		return fmt.Errorf("tracing failed: %w", err)
	}
	_, err = stream.Write(result)
	if err != nil {
		stream.WriteNil()
		return err
	}
	return nil
}

// TraceTx configures a new tracer according to the provided configuration, and
// executes the given message in the provided environment. The return value will
// be tracer dependent.
func TraceTx(
	ctx context.Context,
	message core.Message,
	blockCtx evmtypes.BlockContext,
	txCtx evmtypes.TxContext,
	ibs evmtypes.IntraBlockState,
	config *tracers.TraceConfig,
	chainConfig *chain.Config,
	stream *jsoniter.Stream,
	callTimeout time.Duration,
) error {
	tracer, streaming, cancel, err := AssembleTracer(ctx, config, txCtx.TxHash, stream, callTimeout)
	if err != nil {
		stream.WriteNil()
		return err
	}

	defer cancel()

	execCb := func(evm *vm.EVM, refunds bool) (*core.ExecutionResult, error) {
		gp := new(core.GasPool).AddGas(message.Gas()).AddBlobGas(message.BlobGas())
		return core.ApplyMessage(evm, message, gp, refunds, false /* gasBailout */)
	}

	return ExecuteTraceTx(blockCtx, txCtx, ibs, config, chainConfig, stream, tracer, streaming, execCb)
}

func AssembleTracer(
	ctx context.Context,
	config *tracers.TraceConfig,
	txHash libcommon.Hash,
	stream *jsoniter.Stream,
	callTimeout time.Duration,
) (vm.EVMLogger, bool, context.CancelFunc, error) {
	// Assemble the structured logger or the JavaScript tracer
	switch {
	case config != nil && config.Tracer != nil:
		// Define a meaningful timeout of a single transaction trace
		timeout := callTimeout
		if config.Timeout != nil {
			var err error
			timeout, err = time.ParseDuration(*config.Timeout)
			if err != nil {
				return nil, false, func() {}, err
			}
		}

		// Construct the JavaScript tracer to execute with
		cfg := json.RawMessage("{}")
		if config != nil && config.TracerConfig != nil {
			cfg = *config.TracerConfig
		}
		tracer, err := tracers.New(*config.Tracer, &tracers.Context{TxHash: txHash}, cfg)
		if err != nil {
			return nil, false, func() {}, err
		}

		// Handle timeouts and RPC cancellations
		deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
		go func() {
			<-deadlineCtx.Done()
			tracer.Stop(errors.New("execution timeout"))
		}()

		return tracer, false, cancel, nil
	case config == nil:
		return logger.NewJsonStreamLogger(nil, ctx, stream), true, func() {}, nil
	default:
		return logger.NewJsonStreamLogger(config.LogConfig, ctx, stream), true, func() {}, nil
	}
}

func ExecuteTraceTx(
	blockCtx evmtypes.BlockContext,
	txCtx evmtypes.TxContext,
	ibs evmtypes.IntraBlockState,
	config *tracers.TraceConfig,
	chainConfig *chain.Config,
	stream *jsoniter.Stream,
	tracer vm.EVMLogger,
	streaming bool,
	execCb func(evm *vm.EVM, refunds bool) (*core.ExecutionResult, error),
) error {
	// Run the transaction with tracing enabled.
	evm := vm.NewEVM(blockCtx, txCtx, ibs, chainConfig, vm.Config{Debug: true, Tracer: tracer, NoBaseFee: true})

	var refunds = true
	if config != nil && config.NoRefunds != nil && *config.NoRefunds {
		refunds = false
	}

	if streaming {
		stream.WriteObjectStart()
		stream.WriteObjectField("structLogs")
		stream.WriteArrayStart()
	}

	result, err := execCb(evm, refunds)
	if err != nil {
		if streaming {
			stream.WriteArrayEnd()
			stream.WriteObjectEnd()
		} else {
			stream.WriteNil()
		}
		return fmt.Errorf("tracing failed: %w", err)
	}

	// Depending on the tracer type, format and return the output
	if streaming {
		stream.WriteArrayEnd()
		stream.WriteMore()
		stream.WriteObjectField("gas")
		stream.WriteUint64(result.UsedGas)
		stream.WriteMore()
		stream.WriteObjectField("failed")
		stream.WriteBool(result.Failed())
		stream.WriteMore()
		// If the result contains a revert reason, return it.
		returnVal := hex.EncodeToString(result.Return())
		if len(result.Revert()) > 0 {
			returnVal = hex.EncodeToString(result.Revert())
		}
		stream.WriteObjectField("returnValue")
		stream.WriteString(returnVal)
		stream.WriteObjectEnd()
	} else {
		r, err := tracer.(tracers.Tracer).GetResult()
		if err != nil {
			stream.WriteNil()
			return err
		}

		_, err = stream.Write(r)
		if err != nil {
			stream.WriteNil()
			return err
		}
	}

	return nil
}
