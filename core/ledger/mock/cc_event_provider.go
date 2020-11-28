// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/jxu86/fabric-gm/core/ledger"
)

type ChaincodeLifecycleEventProvider struct {
	RegisterListenerStub        func(string, ledger.ChaincodeLifecycleEventListener)
	registerListenerMutex       sync.RWMutex
	registerListenerArgsForCall []struct {
		arg1 string
		arg2 ledger.ChaincodeLifecycleEventListener
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ChaincodeLifecycleEventProvider) RegisterListener(arg1 string, arg2 ledger.ChaincodeLifecycleEventListener) {
	fake.registerListenerMutex.Lock()
	fake.registerListenerArgsForCall = append(fake.registerListenerArgsForCall, struct {
		arg1 string
		arg2 ledger.ChaincodeLifecycleEventListener
	}{arg1, arg2})
	fake.recordInvocation("RegisterListener", []interface{}{arg1, arg2})
	fake.registerListenerMutex.Unlock()
	if fake.RegisterListenerStub != nil {
		fake.RegisterListenerStub(arg1, arg2)
	}
}

func (fake *ChaincodeLifecycleEventProvider) RegisterListenerCallCount() int {
	fake.registerListenerMutex.RLock()
	defer fake.registerListenerMutex.RUnlock()
	return len(fake.registerListenerArgsForCall)
}

func (fake *ChaincodeLifecycleEventProvider) RegisterListenerCalls(stub func(string, ledger.ChaincodeLifecycleEventListener)) {
	fake.registerListenerMutex.Lock()
	defer fake.registerListenerMutex.Unlock()
	fake.RegisterListenerStub = stub
}

func (fake *ChaincodeLifecycleEventProvider) RegisterListenerArgsForCall(i int) (string, ledger.ChaincodeLifecycleEventListener) {
	fake.registerListenerMutex.RLock()
	defer fake.registerListenerMutex.RUnlock()
	argsForCall := fake.registerListenerArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *ChaincodeLifecycleEventProvider) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.registerListenerMutex.RLock()
	defer fake.registerListenerMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ChaincodeLifecycleEventProvider) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ ledger.ChaincodeLifecycleEventProvider = new(ChaincodeLifecycleEventProvider)
