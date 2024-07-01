package transactions

import (
	"encoding/json"
	"fmt"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"math/big"
	"testing"
)

func TestTokenContract(t *testing.T) {
	tc := NewTokenContract()
	t.Log(tc.Override())
}

func TestJson(t *testing.T) {
	balanceResult := make(map[libcommon.Address]map[libcommon.Address]*big.Int)
	data, err := json.Marshal(balanceResult)
	fmt.Println(string(data), err)
}
