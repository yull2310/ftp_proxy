package main

import (
	"fmt"
	"strings"
	"time"

	logrus_stack "github.com/Gurpartap/logrus-stack"
	"github.com/agclqq/goencryption"
	"github.com/pyama86/pftp/example/webapi"
	"github.com/pyama86/pftp/logaudit"
	"github.com/pyama86/pftp/pftp"
	"github.com/sirupsen/logrus"
)

var confFile = "./config.toml"

// add by yull
var keyStr = "63dTjxISXlwAso0n"
var ivStr = "a1b2c3d4e5f6g7h8"

func init() {
	//modify by yull
	logrus.SetLevel(logrus.InfoLevel)
	//logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetReportCaller(false)
	stackLevels := []logrus.Level{logrus.PanicLevel, logrus.FatalLevel}
	logrus.AddHook(logrus_stack.NewHook(stackLevels, stackLevels))
}

func main() {
	ftpServer, listenaddr, err := pftp.NewFtpServer(confFile)
	if err != nil {
		logrus.Fatal(err)
	}

	addr := strings.Split(*listenaddr, ":")
	logaudit.SetListenPort(addr[1])

	go logauditthread()

	ftpServer.Use("user", User)
	if err := ftpServer.Start(); err != nil {
		logrus.Fatal(err)
	}
}

// modify by yull
func User(c *pftp.Context, param string) error {
	loginInfo, err := webapi.GetLoginInfoFromWebAPI(c, confFile, param)
	if err != nil {
		logrus.Error(fmt.Sprintf("GetLoginInfoFromWebAPI Failed:%v", err))
		return err
	}

	//https://blog.csdn.net/agclqq/article/details/119900624
	passwd, err := goencryption.EasyDecrypt("aes/cbc/pkcs7/base64", loginInfo.RealLoginPasswd, keyStr, ivStr)
	if err != nil {
		logrus.Error(fmt.Sprintf("EasyDecrypt Failed:%v", err))
		return err
	}

	c.RemoteAddr = loginInfo.RemoteAddr
	c.RealLoginUser = loginInfo.RealLoginUser
	c.RealLoginPasswd = passwd
	c.LoginSessionID = loginInfo.LoginSessionID

	return nil
}

func logauditthread() {
	for {
		time.Sleep(2 * time.Second)
		logaudit.RecordAuditLog()
	}
}
