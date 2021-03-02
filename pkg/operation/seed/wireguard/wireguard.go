// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wireguard

import (
	"context"
	"path/filepath"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"k8s.io/apimachinery/pkg/api/meta"
)

type wireguard struct {
	namespace    string
	chartApplier kubernetes.ChartApplier
	chartPath    string
}

// NewWireguard creates a new DeployWaiter for wireguard.
func NewWireguard(
	namespace string,
	chartApplier kubernetes.ChartApplier,
	chartsRootPath string,
) component.DeployWaiter {
	return &wireguard{
		namespace:    namespace,
		chartApplier: chartApplier,
		chartPath:    filepath.Join(chartsRootPath, wireguardReleaseName),
	}
}

func (w *wireguard) Deploy(ctx context.Context) error {
	return w.chartApplier.Apply(ctx, w.chartPath, w.namespace, wireguardReleaseName)
}

func (w *wireguard) Destroy(ctx context.Context) error {
	return w.chartApplier.Delete(
		ctx,
		w.chartPath,
		w.namespace,
		wireguardReleaseName,
		kubernetes.TolerateErrorFunc(meta.IsNoMatchError),
	)
}

func (w *wireguard) Wait(ctx context.Context) error {
	return nil
}

func (w *wireguard) WaitCleanup(ctx context.Context) error {
	return nil
}
