// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import common "github.com/hyperledger/fabric-protos-go/common"
import errors "github.com/jxu86/fabric-gm/common/errors"
import mock "github.com/stretchr/testify/mock"
import peer "github.com/hyperledger/fabric-protos-go/peer"

// StateBasedValidator is an autogenerated mock type for the StateBasedValidator type
type StateBasedValidator struct {
	mock.Mock
}

// PostValidate provides a mock function with given fields: cc, blockNum, txNum, err
func (_m *StateBasedValidator) PostValidate(cc string, blockNum uint64, txNum uint64, err error) {
	_m.Called(cc, blockNum, txNum, err)
}

// PreValidate provides a mock function with given fields: txNum, block
func (_m *StateBasedValidator) PreValidate(txNum uint64, block *common.Block) {
	_m.Called(txNum, block)
}

// Validate provides a mock function with given fields: cc, blockNum, txNum, rwset, prp, ep, endorsements
func (_m *StateBasedValidator) Validate(cc string, blockNum uint64, txNum uint64, rwset []byte, prp []byte, ep []byte, endorsements []*peer.Endorsement) errors.TxValidationError {
	ret := _m.Called(cc, blockNum, txNum, rwset, prp, ep, endorsements)

	var r0 errors.TxValidationError
	if rf, ok := ret.Get(0).(func(string, uint64, uint64, []byte, []byte, []byte, []*peer.Endorsement) errors.TxValidationError); ok {
		r0 = rf(cc, blockNum, txNum, rwset, prp, ep, endorsements)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(errors.TxValidationError)
		}
	}

	return r0
}
