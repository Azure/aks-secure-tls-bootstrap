package client

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("Log tests", func() {
	Context("getLogger tests", func() {
		When("format is json", func() {
			It("should return a new logger with format set to JSON", func() {
				var (
					format = "json"
					debug  = false
				)
				logger := GetLogger(format, debug)
				Expect(logger).ToNot(BeNil())
				Expect(logger.Formatter).To(BeAssignableToTypeOf(&logrus.JSONFormatter{}))
				Expect(logger.Level).To(Equal(logrus.DebugLevel))
			})
		})

		When("format is text", func() {
			It("should return a new logger with format set to text", func() {
				var (
					format = "text"
					debug  = false
				)
				logger := GetLogger(format, debug)
				Expect(logger).ToNot(BeNil())
				Expect(logger.Formatter).To(BeAssignableToTypeOf(&logrus.TextFormatter{}))
				Expect(logger.Level).ToNot(Equal(logrus.DebugLevel))
			})
		})

		When("debug is true", func() {
			It("should return a new logger using the debug level", func() {
				var (
					format = "text"
					debug  = false
				)
				logger := GetLogger(format, debug)
				Expect(logger).ToNot(BeNil())
				Expect(logger.Formatter).To(BeAssignableToTypeOf(&logrus.TextFormatter{}))
				Expect(logger.Level).To(Equal(logrus.DebugLevel))
			})
		})
	})
})
