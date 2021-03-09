// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package secrets

import (
	"encoding/json"
	"fmt"

	"github.com/gardener/gardener/pkg/utils/infodata"
)

// WireguardDataType is the type used to denote an WireguardJSONData structure in the ShootState
const WireguardDataType = infodata.TypeVersion("wireguard")

func init() {
	infodata.Register(WireguardDataType, UnmarshalWireguard)
}

// WireguardJSONData is the json representation of WireguardInfoData used to store Wireguard metadata in the ShootState
type WireguardJSONData struct {
	LocalWireguardIP  string `json:"localWireguardIP"`
	RemoteWireguardIP string `json:"remoteWireguardIP"`
	PeerPresharedKey  string `json:"peerPresharedKey"`
	PrivateKey        string `json:"privateKey"`
	PublicKey         string `json:"publicKey"`
	PeerPublicKey     string `json:"peerPublicKey"`
	RemoteEndpoint    string `json:"remoteEndpoint"`
}

// UnmarshalWireguard unmarshals an WireguardJSONData into a WireguardInfoData struct.
func UnmarshalWireguard(bytes []byte) (infodata.InfoData, error) {
	if bytes == nil {
		return nil, fmt.Errorf("no data given")
	}
	data := &WireguardJSONData{}
	err := json.Unmarshal(bytes, data)
	if err != nil {
		return nil, err
	}

	return NewWireguardInfoData(data.LocalWireguardIP, data.RemoteWireguardIP, data.PeerPresharedKey, data.PrivateKey, data.PublicKey, data.PeerPublicKey, data.RemoteEndpoint), nil
}

// WireguardInfoData holds the keys used for wireguard.
type WireguardInfoData struct {
	LocalWireguardIP  string
	RemoteWireguardIP string
	PeerPresharedKey  string
	ShootPrivateKey   string
	ShootPublicKey    string
	PeerPublicKey     string
	RemoteEndpoint    string
}

// TypeVersion implements InfoData
func (w *WireguardInfoData) TypeVersion() infodata.TypeVersion {
	return WireguardDataType
}

// Marshal implements InfoData
func (w *WireguardInfoData) Marshal() ([]byte, error) {
	return json.Marshal(&WireguardJSONData{w.LocalWireguardIP, w.RemoteWireguardIP, w.PeerPresharedKey, w.ShootPrivateKey, w.ShootPublicKey, w.PeerPublicKey, w.RemoteEndpoint})
}

// NewWireguardInfoData creates a new WireguardInfoData struct with the given keys.
func NewWireguardInfoData(localWireguardIP, remoteWireguardIP, peerPresharedKey, shootPrivateKey, shootPublicKey, peerPublicKey, remoteEndpoint string) infodata.InfoData {
	return &WireguardInfoData{localWireguardIP, remoteWireguardIP, peerPresharedKey, shootPrivateKey, shootPublicKey, peerPublicKey, remoteEndpoint}
}
