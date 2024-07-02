// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package native

import (
	"encoding/json"
	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/hexutility"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/eth/tracers"
	"github.com/ledgerwatch/erigon/turbo/transactions"
	"sync/atomic"
)

func init() {
	register("tokenBalanceTracer", newTokenBalanceTracer)
}

type tokenBalanceTracer struct {
	noopTracer
	contracts    map[common.Address]map[string]struct{}
	topContracts map[common.Address]common.Address // contractAddress: topContractAddress
	interrupt    atomic.Bool                       // Atomic flag to signal execution interruption
	checkTop     bool
}

// newCallTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func newTokenBalanceTracer(ctx *tracers.Context, cfg json.RawMessage) (tracers.Tracer, error) {
	// First callframe contains tx context info
	// and is populated on start and end.
	return &tokenBalanceTracer{
		contracts:    make(map[common.Address]map[string]struct{}),
		topContracts: make(map[common.Address]common.Address),
		checkTop:     false,
	}, nil
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *tokenBalanceTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	t.checkTop = from == transactions.TokenContractCaller && to == transactions.TokenContractAddress
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *tokenBalanceTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// skip if the previous op caused an error
	if err != nil {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}
	// here is the code only for token_contract.sol
	// when we simulate the balanceOf of the contracts
	// for other transaction or simulation, we won't use topContract
	contractAddress := scope.Contract.Address()
	if t.checkTop {
		caller := scope.Contract.Caller()
		if caller != transactions.TokenContractCaller && caller != transactions.TokenContractAddress {
			if _, ok := t.topContracts[contractAddress]; !ok {
				if topContract, hasCaller := t.topContracts[caller]; !hasCaller {
					t.topContracts[contractAddress] = caller
				} else {
					t.topContracts[contractAddress] = topContract
				}
			}
		}
	}

	switch op {
	case vm.KECCAK256:
		stack := scope.Stack
		stackData := stack.Data
		offset := stackData[len(stackData)-1]
		size := stackData[len(stackData)-2]
		data := scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))

		if _, ok := t.contracts[contractAddress]; !ok {
			t.contracts[contractAddress] = make(map[string]struct{})
		}
		t.contracts[contractAddress][hexutility.Encode(data)] = struct{}{}
	}
}

type TokenBalanceResult struct {
	Contracts    map[common.Address][]string       `json:"contracts"`
	TopContracts map[common.Address]common.Address `json:"topContracts"`
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *tokenBalanceTracer) GetResult() (json.RawMessage, error) {
	contracts := make(map[common.Address][]string)
	for k, vs := range t.contracts {
		contracts[k] = make([]string, 0)
		for v := range vs {
			contracts[k] = append(contracts[k], v)
		}
	}

	tbr := TokenBalanceResult{
		Contracts:    contracts,
		TopContracts: t.topContracts,
	}

	res, err := json.Marshal(tbr)
	if err != nil {
		return nil, err
	}

	t.contracts = make(map[common.Address]map[string]struct{})
	t.topContracts = make(map[common.Address]common.Address)

	return json.RawMessage(res), nil
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *tokenBalanceTracer) Stop(err error) {
	t.interrupt.Store(true)
}
