package logaudit

import (
	"os"
	"sync"
	"time"
)

var g_arrLogs []string
var g_Mutex sync.Mutex
var g_listenPort string

func SetListenPort(port string) {
	g_listenPort = port
}

func AddAuditLog(log string) {
	g_Mutex.Lock()
	g_arrLogs = append(g_arrLogs, log)
	g_Mutex.Unlock()
}

func RecordAuditLog() {
	g_Mutex.Lock()
	if len(g_arrLogs) == 0 {
		g_Mutex.Unlock()
		return
	}

	logstmp := g_arrLogs
	g_arrLogs = []string{}
	g_Mutex.Unlock()

	currentTime := time.Now().Format("20060102150405")
	logfilename := "ftp_audit_" + g_listenPort + "_" + currentTime + ".json"
	filehandler, err := os.Create(logfilename)
	if err != nil {
		return
	}
	defer filehandler.Close()
	for index := range logstmp {
		filehandler.WriteString(logstmp[index])
	}

	logstmp = []string{}
}
