// Copyright 2024 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/plutigo/data"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"golang.org/x/crypto/blake2b"
)

const (
	Blake2b256Size = 32
	Blake2b224Size = 28
	Blake2b160Size = 20
)

type Blake2b256 [Blake2b256Size]byte

func NewBlake2b256(data []byte) Blake2b256 {
	b := Blake2b256{}
	copy(b[:], data)
	return b
}

func (b Blake2b256) String() string {
	return hex.EncodeToString(b[:])
}

func (b Blake2b256) Bytes() []byte {
	return b[:]
}

func (b Blake2b256) ToPlutusData() data.PlutusData {
	return data.NewByteString(b[:])
}

// Blake2b256Hash generates a Blake2b-256 hash from the provided data
func Blake2b256Hash(data []byte) Blake2b256 {
	tmpHash, err := blake2b.New(Blake2b256Size, nil)
	if err != nil {
		panic(
			fmt.Sprintf(
				"unexpected error generating empty blake2b hash: %s",
				err,
			),
		)
	}
	tmpHash.Write(data)
	return Blake2b256(tmpHash.Sum(nil))
}

type Blake2b224 [Blake2b224Size]byte

func NewBlake2b224(data []byte) Blake2b224 {
	b := Blake2b224{}
	copy(b[:], data)
	return b
}

func (b Blake2b224) String() string {
	return hex.EncodeToString(b[:])
}

func (b Blake2b224) Bytes() []byte {
	return b[:]
}

func (b Blake2b224) ToPlutusData() data.PlutusData {
	return data.NewByteString(b[:])
}

func (b Blake2b224) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

// Blake2b224Hash generates a Blake2b-224 hash from the provided data
func Blake2b224Hash(data []byte) Blake2b224 {
	tmpHash, err := blake2b.New(Blake2b224Size, nil)
	if err != nil {
		panic(
			fmt.Sprintf(
				"unexpected error generating empty blake2b hash: %s",
				err,
			),
		)
	}
	tmpHash.Write(data)
	return Blake2b224(tmpHash.Sum(nil))
}

type Blake2b160 [Blake2b160Size]byte

func NewBlake2b160(data []byte) Blake2b160 {
	b := Blake2b160{}
	copy(b[:], data)
	return b
}

func (b Blake2b160) String() string {
	return hex.EncodeToString(b[:])
}

func (b Blake2b160) Bytes() []byte {
	return b[:]
}

func (b Blake2b160) ToPlutusData() data.PlutusData {
	return data.NewByteString(b[:])
}

// Blake2b160Hash generates a Blake2b-160 hash from the provided data
func Blake2b160Hash(data []byte) Blake2b160 {
	tmpHash, err := blake2b.New(Blake2b160Size, nil)
	if err != nil {
		panic(
			fmt.Sprintf(
				"unexpected error generating empty blake2b hash: %s",
				err,
			),
		)
	}
	tmpHash.Write(data)
	return Blake2b160(tmpHash.Sum(nil))
}

type (
	MultiAssetTypeOutput = *big.Int
	MultiAssetTypeMint   = *big.Int
)

// MultiAsset represents a collection of policies, assets, and quantities. It's used for
// TX outputs (uint64) and TX asset minting (int64 to allow for negative values for burning)
type MultiAsset[T int64 | uint64 | *big.Int] struct {
	data map[Blake2b224]map[cbor.ByteString]T
}

// NewMultiAsset creates a MultiAsset with the specified data
func NewMultiAsset[T int64 | uint64 | *big.Int](
	data map[Blake2b224]map[cbor.ByteString]T,
) MultiAsset[T] {
	if data == nil {
		data = make(map[Blake2b224]map[cbor.ByteString]T)
	}
	return MultiAsset[T]{data: data}
}

// multiAssetJson is a convenience type for marshaling/unmarshaling MultiAsset to/from JSON
type multiAssetJson[T int64 | uint64 | *big.Int] struct {
	Name        string `json:"name"`
	NameHex     string `json:"nameHex"`
	PolicyId    string `json:"policyId"`
	Fingerprint string `json:"fingerprint"`
	Amount      string `json:"amount"`
}

func (m *MultiAsset[T]) UnmarshalCBOR(data []byte) error {
	_, err := cbor.Decode(data, &(m.data))
	return err
}

func (m *MultiAsset[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Encode(&(m.data))
}

func (m MultiAsset[T]) MarshalJSON() ([]byte, error) {
	tmpAssets := []multiAssetJson[T]{}
	for policyId, policyData := range m.data {
		for assetName, amount := range policyData {
			tmpObj := multiAssetJson[T]{
				Name:     string(assetName.Bytes()),
				NameHex:  hex.EncodeToString(assetName.Bytes()),
				Amount:   amountToString(amount),
				PolicyId: policyId.String(),
				Fingerprint: NewAssetFingerprint(
					policyId.Bytes(),
					assetName.Bytes(),
				).String(),
			}
			tmpAssets = append(tmpAssets, tmpObj)
		}
	}
	return json.Marshal(&tmpAssets)
}

func (m *MultiAsset[T]) UnmarshalJSON(data []byte) error {
	tmpAssets := []multiAssetJson[T]{}
	if err := json.Unmarshal(data, &tmpAssets); err != nil {
		return err
	}
	if m.data == nil {
		m.data = make(map[Blake2b224]map[cbor.ByteString]T)
	}
	for _, tmp := range tmpAssets {
		policyBytes, err := hex.DecodeString(tmp.PolicyId)
		if err != nil {
			return err
		}
		var policy Blake2b224
		copy(policy[:], policyBytes)
		nameBytes, err := hex.DecodeString(tmp.NameHex)
		if err != nil {
			return err
		}
		amount, err := parseAmount[T](tmp.Amount)
		if err != nil {
			return err
		}
		if _, ok := m.data[policy]; !ok {
			m.data[policy] = make(map[cbor.ByteString]T)
		}
		m.data[policy][cbor.NewByteString(nameBytes)] = amount
	}
	return nil
}

func (m *MultiAsset[T]) ToPlutusData() data.PlutusData {
	tmpData := make([][2]data.PlutusData, 0, len(m.data))
	// Sort policy IDs
	policyKeys := slices.Collect(maps.Keys(m.data))
	slices.SortFunc(
		policyKeys,
		func(a, b Blake2b224) int { return bytes.Compare(a.Bytes(), b.Bytes()) },
	)
	for _, policyId := range policyKeys {
		policyData := m.data[policyId]
		tmpPolicyData := make([][2]data.PlutusData, 0, len(policyData))
		// Sort asset names
		assetKeys := slices.Collect(maps.Keys(policyData))
		slices.SortFunc(
			assetKeys,
			func(a, b cbor.ByteString) int { return bytes.Compare(a.Bytes(), b.Bytes()) },
		)
		for _, assetName := range assetKeys {
			amount := policyData[assetName]
			tmpPolicyData = append(
				tmpPolicyData,
				[2]data.PlutusData{
					data.NewByteString(assetName.Bytes()),
					data.NewInteger(amountToBigInt(amount)),
				},
			)
		}
		tmpData = append(
			tmpData,
			[2]data.PlutusData{
				data.NewByteString(policyId.Bytes()),
				data.NewMap(tmpPolicyData),
			},
		)
	}
	return data.NewMap(tmpData)
}

func (m *MultiAsset[T]) Policies() []Blake2b224 {
	ret := []Blake2b224{}
	for policyId := range m.data {
		ret = append(ret, policyId)
	}
	return ret
}

func (m *MultiAsset[T]) Assets(policyId Blake2b224) [][]byte {
	assets, ok := m.data[policyId]
	if !ok {
		return nil
	}
	ret := [][]byte{}
	for assetName := range assets {
		ret = append(ret, assetName.Bytes())
	}
	return ret
}

func (m *MultiAsset[T]) Asset(policyId Blake2b224, assetName []byte) T {
	policy, ok := m.data[policyId]
	if !ok {
		var zero T
		return zero
	}
	return policy[cbor.NewByteString(assetName)]
}

func (m *MultiAsset[T]) Add(assets *MultiAsset[T]) {
	if assets == nil {
		return
	}
	for policy, assets := range assets.data {
		for asset, amount := range assets {
			existing := m.Asset(policy, asset.Bytes())
			newAmount := addAmounts(existing, amount)
			if _, ok := m.data[policy]; !ok {
				m.data[policy] = make(map[cbor.ByteString]T)
			}
			m.data[policy][asset] = newAmount
		}
	}
}

func (m *MultiAsset[T]) Compare(assets *MultiAsset[T]) bool {
	// Normalize data for easier comparison
	tmpData := m.normalize()
	otherData := assets.normalize()
	// Compare policy counts
	if len(otherData) != len(tmpData) {
		return false
	}
	for policy, assets := range otherData {
		// Compare asset counts for policy
		if len(assets) != len(tmpData[policy]) {
			return false
		}
		for asset, amount := range assets {
			// Compare quantity of specific asset
			if !amountsEqual(amount, m.Asset(policy, asset.Bytes())) {
				return false
			}
		}
	}
	return true
}

func (m *MultiAsset[T]) normalize() map[Blake2b224]map[cbor.ByteString]T {
	ret := map[Blake2b224]map[cbor.ByteString]T{}
	if m == nil || m.data == nil {
		return ret
	}
	for policy, assets := range m.data {
		for asset, amount := range assets {
			if !amountIsZero(amount) {
				if _, ok := ret[policy]; !ok {
					ret[policy] = make(map[cbor.ByteString]T)
				}
				// copy amount for big.Int to avoid aliasing
				switch v := any(amount).(type) {
				case *big.Int:
					ret[policy][asset] = any(new(big.Int).Set(v)).(T)
				default:
					ret[policy][asset] = amount
				}
			}
		}
	}
	return ret
}

// String returns a stable, human-friendly representation of the MultiAsset.
// Output format: [<policyId>.<assetNameHex>=<amount>, ...] sorted by policyId, then asset name
func (m *MultiAsset[T]) String() string {
	if m == nil {
		return "[]"
	}
	norm := m.normalize()
	if len(norm) == 0 {
		return "[]"
	}

	policies := slices.Collect(maps.Keys(norm))
	slices.SortFunc(policies, func(a, b Blake2b224) int { return bytes.Compare(a.Bytes(), b.Bytes()) })

	var b strings.Builder
	b.WriteByte('[')
	first := true
	for _, pid := range policies {
		assets := norm[pid]
		names := slices.Collect(maps.Keys(assets))
		slices.SortFunc(names, func(a, b cbor.ByteString) int { return bytes.Compare(a.Bytes(), b.Bytes()) })

		for _, name := range names {
			if !first {
				b.WriteString(", ")
			}
			first = false
			b.WriteString(pid.String())
			b.WriteByte('.')
			b.WriteString(hex.EncodeToString(name.Bytes()))
			b.WriteByte('=')
			b.WriteString(amountToString(assets[name]))
		}
	}
	b.WriteByte(']')
	return b.String()
}

// Helper functions for generic amount handling

func addAmounts[T int64 | uint64 | *big.Int](a, b T) T {
	switch av := any(a).(type) {
	case *big.Int:
		var aInt, bInt *big.Int
		if av != nil {
			aInt = av
		} else {
			aInt = new(big.Int)
		}
		bv := any(b).(*big.Int)
		if bv != nil {
			bInt = bv
		} else {
			bInt = new(big.Int)
		}
		return any(new(big.Int).Add(aInt, bInt)).(T)
	case int64:
		return any(av + any(b).(int64)).(T)
	default:
		var zero T
		return zero
	}
}

func amountsEqual[T int64 | uint64 | *big.Int](a, b T) bool {
	switch av := any(a).(type) {
	case *big.Int:
		bv := any(b).(*big.Int)
		if av == nil && bv == nil {
			return true
		}
		if av == nil {
			return bv.Sign() == 0
		}
		if bv == nil {
			return av.Sign() == 0
		}
		return av.Cmp(bv) == 0
	case int64:
		return av == any(b).(int64)
	default:
		return false
	}
}

func amountIsZero[T int64 | uint64 | *big.Int](a T) bool {
	switch av := any(a).(type) {
	case *big.Int:
		if av == nil {
			return true
		}
		return av.Sign() == 0
	case int64:
		return av == 0
	default:
		return false
	}
}

func amountToString[T int64 | uint64 | *big.Int](a T) string {
	switch av := any(a).(type) {
	case *big.Int:
		if av == nil {
			return "0"
		}
		return av.String()
	case int64:
		return strconv.FormatInt(av, 10)
	default:
		return "0"
	}
}

func amountToBigInt[T int64 | uint64 | *big.Int](a T) *big.Int {
	switch av := any(a).(type) {
	case *big.Int:
		if av == nil {
			return new(big.Int)
		}
		return new(big.Int).Set(av)
	case int64:
		return big.NewInt(int64(av))
	default:
		return new(big.Int)
	}
}

func parseAmount[T int64 | uint64 | *big.Int](s string) (T, error) {
	var zero T
	switch any(zero).(type) {
	case *big.Int:
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return zero, fmt.Errorf("invalid big.Int: %s", s)
		}
		return any(v).(T), nil
	case int64:
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return zero, err
		}
		return any(i).(T), nil
	default:
		return zero, fmt.Errorf("unsupported amount type")
	}
}

type AssetFingerprint struct {
	policyId  []byte
	assetName []byte
}

func NewAssetFingerprint(policyId []byte, assetName []byte) AssetFingerprint {
	return AssetFingerprint{
		policyId:  policyId,
		assetName: assetName,
	}
}

func (a AssetFingerprint) Hash() Blake2b160 {
	tmpHash, err := blake2b.New(20, nil)
	if err != nil {
		panic(
			fmt.Sprintf(
				"unexpected error creating empty blake2b hash: %s",
				err,
			),
		)
	}
	tmpHash.Write(a.policyId)
	tmpHash.Write(a.assetName)
	return NewBlake2b160(tmpHash.Sum(nil))
}

func (a AssetFingerprint) String() string {
	// Convert data to base32 and encode as bech32
	convData, err := bech32.ConvertBits(a.Hash().Bytes(), 8, 5, true)
	if err != nil {
		panic(
			fmt.Sprintf("unexpected error converting data to base32: %s", err),
		)
	}
	encoded, err := bech32.Encode("asset", convData)
	if err != nil {
		panic(fmt.Sprintf("unexpected error encoding data as bech32: %s", err))
	}
	return encoded
}

type PoolId [28]byte

func NewPoolIdFromBech32(poolId string) (PoolId, error) {
	var p PoolId
	_, data, err := bech32.DecodeNoLimit(poolId)
	if err != nil {
		return p, err
	}
	decoded, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return p, err
	}
	if len(decoded) != len(p) {
		return p, fmt.Errorf("invalid pool ID length: %d", len(decoded))
	}
	p = PoolId(decoded)
	return p, err
}

func (p PoolId) String() string {
	// Convert data to base32 and encode as bech32
	convData, err := bech32.ConvertBits(p[:], 8, 5, true)
	if err != nil {
		panic(
			fmt.Sprintf("unexpected error converting data to base32: %s", err),
		)
	}
	encoded, err := bech32.Encode("pool", convData)
	if err != nil {
		panic(fmt.Sprintf("unexpected error encoding data as bech32: %s", err))
	}
	return encoded
}

// IssuerVkey represents the verification key for the stake pool that minted a block
type IssuerVkey [32]byte

func (i IssuerVkey) Hash() Blake2b224 {
	hash, err := blake2b.New(28, nil)
	if err != nil {
		panic(
			fmt.Sprintf(
				"unexpected error creating empty blake2b hash: %s",
				err,
			),
		)
	}
	hash.Write(i[:])
	return Blake2b224(hash.Sum(nil))
}

func (i IssuerVkey) PoolId() string {
	// Convert data to base32 and encode as bech32
	convData, err := bech32.ConvertBits(i.Hash().Bytes(), 8, 5, true)
	if err != nil {
		panic(
			fmt.Sprintf("unexpected error converting data to base32: %s", err),
		)
	}
	encoded, err := bech32.Encode("pool", convData)
	if err != nil {
		panic(fmt.Sprintf("unexpected error encoding data as bech32: %s", err))
	}
	return encoded
}

// ExUnits represents the steps and memory usage for script execution
type ExUnits struct {
	cbor.StructAsArray
	Memory int64
	Steps  int64
}

// GenesisRat is a convenience type for cbor.Rat
type GenesisRat = cbor.Rat
