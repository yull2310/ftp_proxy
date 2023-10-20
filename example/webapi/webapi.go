package webapi

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unsafe"

	"github.com/BurntSushi/toml"
	"github.com/pyama86/pftp/pftp"
	"github.com/sirupsen/logrus"
)

type config struct {
	Apiserver serverConfig `toml:"webapiserver"`
}

type serverConfig struct {
	URI string `toml:"uri"`
}

// modify by yull
type Response struct {
	ResultCode      int    `json:"resultCode"`
	ResultDesc      string `json:"resultDesc"`
	RemoteAddr      string `json:"remoteAddr"`
	RealLoginUser   string `json:"realLoginUser"`
	RealLoginPasswd string `json:"realLoginPasswd"`
	LoginSessionID  string `json:"loginSessionID"`
}

func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// modify by yull
func RequestToServer(requestURL string) (*Response, error) {
	//https://juejin.cn/post/7132752655243280420
	tr := &http.Transport{
		//Do not verify peer certificate
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(requestURL)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var decodedBody = new(Response)
	json.Unmarshal(respBody, &decodedBody)

	if decodedBody.ResultCode != 200 {
		if len(decodedBody.ResultDesc) > 0 {
			return nil, errors.New(decodedBody.ResultDesc)
		} else {
			return nil, errors.New(BytesToString(respBody))
		}
	}

	return decodedBody, nil
}

// modify by yull
func GetLoginInfoFromWebAPI(c *pftp.Context, path string, param string) (*Response, error) {
	var conf config
	_, err := toml.DecodeFile(path, &conf)
	if err != nil {
		return nil, err
	}

	loginInfo, err := RequestToServer(fmt.Sprintf(conf.Apiserver.URI, param))
	if err != nil {
		logrus.Info(fmt.Sprintf("GetLoginInfoFromWebAPI, RequestToServer error: %s", fmt.Sprintf(conf.Apiserver.URI, param)))
		return nil, err
	}

	logrus.Info(fmt.Sprintf("GetLoginInfoFromWebAPI Success, URL:%s", fmt.Sprintf(conf.Apiserver.URI, param)))
	return loginInfo, nil
}
