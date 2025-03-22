// Copyright 2018 The go-ethereum Authors
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

package core

import (
	"context"

	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

// StdIOUI 通过标准输入输出与 RPC 客户端交互的 UI。
type StdIOUI struct {
	client *rpc.Client
}

// 以下方法通过 dispatch 或 notify 调用远程服务：
//
// ApproveTx: 批准交易签名。
// ApproveSignData: 批准数据签名。
// ApproveListing: 批准账户列出。
// ApproveNewAccount: 批准新账户创建。
// ShowError: 显示错误消息。
// ShowInfo: 显示信息消息。
// OnApprovedTx: 通知已签名交易。
// OnSignerStartup: 通知签名者启动。
// OnInputRequired: 请求用户输入。

func NewStdIOUI() *StdIOUI {
	client, err := rpc.DialContext(context.Background(), "stdio://")
	if err != nil {
		log.Crit("Could not create stdio client", "err", err)
	}
	ui := &StdIOUI{client: client}
	return ui
}

func (ui *StdIOUI) RegisterUIServer(api *UIServerAPI) {
	ui.client.RegisterName("clef", api)
}

// dispatch sends a request over the stdio
// dispatch 通过标准输入输出发送请求
// 通过 RPC 发送请求并等待响应。
func (ui *StdIOUI) dispatch(serviceMethod string, args interface{}, reply interface{}) error {
	err := ui.client.Call(&reply, serviceMethod, args)
	if err != nil {
		log.Info("Error", "exc", err.Error())
	}
	return err
}

// notify sends a request over the stdio, and does not listen for a response
// notify 通过标准输入输出发送请求，且不监听响应
// 通过 RPC 发送通知（无响应）。
func (ui *StdIOUI) notify(serviceMethod string, args interface{}) error {
	ctx := context.Background()
	err := ui.client.Notify(ctx, serviceMethod, args)
	if err != nil {
		log.Info("Error", "exc", err.Error())
	}
	return err
}

func (ui *StdIOUI) ApproveTx(request *SignTxRequest) (SignTxResponse, error) {
	var result SignTxResponse
	err := ui.dispatch("ui_approveTx", request, &result)
	return result, err
}

func (ui *StdIOUI) ApproveSignData(request *SignDataRequest) (SignDataResponse, error) {
	var result SignDataResponse
	err := ui.dispatch("ui_approveSignData", request, &result)
	return result, err
}

func (ui *StdIOUI) ApproveListing(request *ListRequest) (ListResponse, error) {
	var result ListResponse
	err := ui.dispatch("ui_approveListing", request, &result)
	return result, err
}

func (ui *StdIOUI) ApproveNewAccount(request *NewAccountRequest) (NewAccountResponse, error) {
	var result NewAccountResponse
	err := ui.dispatch("ui_approveNewAccount", request, &result)
	return result, err
}

func (ui *StdIOUI) ShowError(message string) {
	err := ui.notify("ui_showError", &Message{message})
	if err != nil {
		log.Info("Error calling 'ui_showError'", "exc", err.Error(), "msg", message)
	}
}

func (ui *StdIOUI) ShowInfo(message string) {
	err := ui.notify("ui_showInfo", Message{message})
	if err != nil {
		log.Info("Error calling 'ui_showInfo'", "exc", err.Error(), "msg", message)
	}
}
func (ui *StdIOUI) OnApprovedTx(tx ethapi.SignTransactionResult) {
	err := ui.notify("ui_onApprovedTx", tx)
	if err != nil {
		log.Info("Error calling 'ui_onApprovedTx'", "exc", err.Error(), "tx", tx)
	}
}

func (ui *StdIOUI) OnSignerStartup(info StartupInfo) {
	err := ui.notify("ui_onSignerStartup", info)
	if err != nil {
		log.Info("Error calling 'ui_onSignerStartup'", "exc", err.Error(), "info", info)
	}
}
func (ui *StdIOUI) OnInputRequired(info UserInputRequest) (UserInputResponse, error) {
	var result UserInputResponse
	err := ui.dispatch("ui_onInputRequired", info, &result)
	if err != nil {
		log.Info("Error calling 'ui_onInputRequired'", "exc", err.Error(), "info", info)
	}
	return result, err
}
