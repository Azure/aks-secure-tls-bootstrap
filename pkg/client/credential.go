package client

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	"github.com/sirupsen/logrus"
)

func GetExecCredential(logger *logrus.Logger) (*datamodel.ExecCredential, error) {
	logger.Debugf("parsing %s variable", kubernetesExecInfoVarName)
	kubernetesExecInfoVar := os.Getenv(kubernetesExecInfoVarName)
	if kubernetesExecInfoVar == "" {
		return nil, fmt.Errorf("%s variable not found", kubernetesExecInfoVarName)
	}

	execCredential := &datamodel.ExecCredential{}
	if err := json.Unmarshal([]byte(kubernetesExecInfoVar), execCredential); err != nil {
		return nil, err
	}

	return execCredential, nil
}
