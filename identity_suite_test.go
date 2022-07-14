package identity_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redhatinsights/identity"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var validJson = [...]string{
	`{ "identity": {"account_number": "540155", "org_id": "1979710", "type": "User", "internal": {"org_id": "1979710"} } }`,
	`{ "identity": {"account_number": "540155", "org_id": "1979710", "type": "Associate", "internal": {"org_id": "1979710"} } }`,
	`{ "identity": {"account_number": "540155", "type": "Associate", "internal": {"org_id": "1979710"} } }`,
}

func GetTestHandler(allowPass bool) http.HandlerFunc {
	fn := func(rw http.ResponseWriter, req *http.Request) {
		if !allowPass {
			panic("test entered test handler, this should not happen")
		}
	}

	return http.HandlerFunc(fn)
}

func boilerWithCustomHandler(req *http.Request, expectedStatusCode int, expectedBody string, handlerFunc http.HandlerFunc) {
	rr := httptest.NewRecorder()

	handler := identity.BasePolicy(handlerFunc)
	handler = identity.Extractor(handler)
	handler.ServeHTTP(rr, req)

	Expect(rr.Body.String()).To(Equal(expectedBody))
	Expect(rr.Code).To(Equal(expectedStatusCode))
}

func boiler(req *http.Request, expectedStatusCode int, expectedBody string) {
	boilerWithCustomHandler(req, expectedStatusCode, expectedBody, GetTestHandler(expectedStatusCode == http.StatusOK))
}

func getBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func TestIdentity(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Identity Suite")
}

var _ = Describe("Identity", func() {
	var req *http.Request

	BeforeEach(func() {
		r, err := http.NewRequest("GET", "/api/entitlements/v1/services/", nil)
		if err != nil {
			panic("Test error unable to get a NewRequest")
		}
		req = r
	})

	Context("With a valid x-rh-id header", func() {
		It("should 200 and set the org_id on the context", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity))

				boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
					fn := func(rw http.ResponseWriter, nreq *http.Request) {
						id, ok := identity.Get(nreq.Context())
						Expect(ok).To(BeTrue())
						Expect(id.Identity.OrgID).To(Equal("1979710"))
						Expect(id.Identity.Internal.OrgID).To(Equal("1979710"))
						Expect(id.Identity.AccountNumber).To(Equal("540155"))
					}
					return http.HandlerFunc(fn)
				}())
			}
		})
		It("should be able to return the header again if headers are requested", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity))

				boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
					fn := func(rw http.ResponseWriter, nreq *http.Request) {
						h, _ := identity.GetIdentityHeader(nreq.Context())
						Expect(h).ToNot(BeEmpty())
					}
					return http.HandlerFunc(fn)
				}())
			}
		})
	})
	Context("With a missing x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			boiler(req, 400, "Bad Request: missing x-rh-identity header\n")
		})
		It("should return empty string if headers are requested", func() {
			boilerWithCustomHandler(req, 400, "Bad Request: missing x-rh-identity header\n", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					h, ok := identity.GetIdentityHeader(nreq.Context())
					Expect(ok).To(BeFalse())
					Expect(h).To(BeEmpty())
				}
				return http.HandlerFunc(fn)
			}())
		})
	})

	Context("With invalid b64 data in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", "="+getBase64(jsonIdentity))
				boiler(req, 400, "Bad Request: unable to b64 decode x-rh-identity header\n")
			}
		})
	})

	Context("With invalid json data (valid b64) in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity+"}"))
				boiler(req, 400, "Bad Request: x-rh-identity header is does not contain valid JSON\n")
			}
		})
		It("should return empty string if headers are requested", func() {
			for _, jsonIdentity := range validJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity+"}"))
				boilerWithCustomHandler(req, 400, "Bad Request: x-rh-identity header is does not contain valid JSON\n", func() http.HandlerFunc {
					fn := func(rw http.ResponseWriter, nreq *http.Request) {
						h, ok := identity.GetIdentityHeader(nreq.Context())
						Expect(ok).To(BeFalse())
						Expect(h).To(BeEmpty())
					}
					return http.HandlerFunc(fn)
				}())
			}
		})
	})

	Context("With missing account_number in the x-rh-id header", func() {
		It("should 200", func() {
			req.Header.Set("x-rh-identity", getBase64(`{ "identity": {"org_id": "1979710", "auth_type": "basic-auth", "type": "Associate", "internal": {"org_id": "1979710"} } }`))
			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id, _ := identity.Get(nreq.Context())
					Expect(id.Identity.OrgID).To(Equal("1979710"))
					Expect(id.Identity.Internal.OrgID).To(Equal("1979710"))
					Expect(id.Identity.AccountNumber).To(Equal(""))
				}
				return http.HandlerFunc(fn)
			}())
		})
	})

	Context("With a valid x-rh-id header", func() {
		It("should 200 and set the type to associate", func() {
			req.Header.Set("x-rh-identity", getBase64(`{ "identity": {"type": "Associate"} }`))

			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id, _ := identity.Get(nreq.Context())
					Expect(id.Identity.Type).To(Equal("Associate"))
				}
				return http.HandlerFunc(fn)
			}())
		})
	})

	Context("With rhel and ansible entitlement set in the x-rh-id header", func() {
		It("should 200 and set the entitlement", func() {
			req.Header.Set("x-rh-identity", getBase64(`{ "identity": {"type": "Associate", "internal": {"org_id": "1979710"} }, "entitlements": {"rhel": {"is_entitled": true}, "ansible": {"is_entitled": true, "is_trial": true} } }`))

			boilerWithCustomHandler(req, 200, "", func() http.HandlerFunc {
				fn := func(rw http.ResponseWriter, nreq *http.Request) {
					id, _ := identity.Get(nreq.Context())
					Expect(id.Entitlements["rhel"].IsEntitled).To(Equal(true))
					Expect(id.Entitlements["rhel"].IsTrial).To(Equal(false))
					Expect(id.Entitlements["ansible"].IsEntitled).To(Equal(true))
					Expect(id.Entitlements["ansible"].IsTrial).To(Equal(true))
				}
				return http.HandlerFunc(fn)
			}())
		})
	})

	Context("With missing org_id in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			var missingOrgIDJson = [...]string{
				`{ "identity": {"account_number": "540155", "type": "User", "internal": {} } }`,
				`{ "identity": {"account_number": "540155", "org_id": "1979710", "type": "User", "internal": {} } }`,
			}

			for _, jsonIdentity := range missingOrgIDJson {
				req.Header.Set("x-rh-identity", getBase64(jsonIdentity))
				boiler(req, 400, "Bad Request: x-rh-identity header has an invalid or missing org_id\n")
			}
		})
	})

	Context("With missing type in the x-rh-id header", func() {
		It("should throw a 400 with a descriptive message", func() {
			req.Header.Set("x-rh-identity", getBase64(`{"identity":{"account_number":"540155","type":"", "org_id":"1979710", "internal":{"org_id":"1979710"}}}`))
			boiler(req, 400, "Bad Request: x-rh-identity header is missing type\n")
		})
	})

	Context("Without Extractor installed", func() {
		It("should throw a 401", func() {
			rr := httptest.NewRecorder()
			handler := identity.BasePolicy(GetTestHandler(true))
			handler.ServeHTTP(rr, req)

			Expect(rr.Body.String()).To(Equal("Unauthorized: missing identity header\n"))
			Expect(rr.Code).To(Equal(401))
		})
	})
})
