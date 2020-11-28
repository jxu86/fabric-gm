// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	cluster "github.com/jxu86/fabric-gm/orderer/common/cluster"
	mock "github.com/stretchr/testify/mock"
)

// ChannelLister is an autogenerated mock type for the ChannelLister type
type ChannelLister struct {
	mock.Mock
}

// Channels provides a mock function with given fields:
func (_m *ChannelLister) Channels() []cluster.ChannelGenesisBlock {
	ret := _m.Called()

	var r0 []cluster.ChannelGenesisBlock
	if rf, ok := ret.Get(0).(func() []cluster.ChannelGenesisBlock); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]cluster.ChannelGenesisBlock)
		}
	}

	return r0
}

// Close provides a mock function with given fields:
func (_m *ChannelLister) Close() {
	_m.Called()
}
