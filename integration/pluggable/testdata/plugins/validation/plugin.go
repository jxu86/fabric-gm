/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	validation "github.com/jxu86/fabric-gm/core/handlers/validation/api"
	"github.com/jxu86/fabric-gm/core/handlers/validation/builtin"
	"github.com/jxu86/fabric-gm/integration/pluggable"
)

// go build -buildmode=plugin -o plugin.so

// NewPluginFactory is the function ran by the plugin infrastructure to create a validation plugin factory.
func NewPluginFactory() validation.PluginFactory {
	pluggable.PublishValidationPluginActivation()
	return &builtin.DefaultValidationFactory{}
}
