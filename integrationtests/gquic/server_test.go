package gquic_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/toyserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Server tests", func() {
	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		var client *http.Client

		BeforeEach(func() {
			toyserver.New()
			// prepare the h2quic.client
			certPool := x509.NewCertPool()
			certPool.AddCert(toyserver.CACert())
			client = &http.Client{
				Transport: &h2quic.RoundTripper{
					TLSClientConfig: &tls.Config{RootCAs: certPool},
					QuicConfig: &quic.Config{
						Versions: []protocol.VersionNumber{version},
					},
				},
			}
		})

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			It("downloads a hello", func() {
				data := []byte("Hello world!\n")
				toyserver.CreateDownloadFile("hello", data)
				toyserver.Start(version)
				defer toyserver.Stop()

				rsp, err := client.Get(fmt.Sprintf("https://quic.clemente.io:%d/hello", toyserver.Port()))
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 5*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(data))
			})

			It("downloads a small file", func() {
				toyserver.CreateDownloadFile("file.dat", testserver.PRData)
				toyserver.Start(version)
				defer toyserver.Stop()

				rsp, err := client.Get(fmt.Sprintf("https://quic.clemente.io:%d/file.dat", toyserver.Port()))
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 5*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(testserver.PRData))
			})

			It("downloads a large file", func() {
				toyserver.CreateDownloadFile("file.dat", testserver.PRDataLong)
				toyserver.Start(version)
				defer toyserver.Stop()

				rsp, err := client.Get(fmt.Sprintf("https://quic.clemente.io:%d/file.dat", toyserver.Port()))
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 20*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(testserver.PRDataLong))
			})
		})
	}
})
