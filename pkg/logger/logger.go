package logger

import (
	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

func Init(level logrus.Level) {
	Log.SetLevel(level)
}
