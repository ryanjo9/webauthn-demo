package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fxamacker/webauthn"
	"github.com/ryanjo9/webauthn-demo/server/mongodb"
)

var cfg = &webauthn.Config{
	RPID:                    "webauthndemo.ryanjolaughlin.com",
	RPName:                  "Ryan O'Laughlin's website",
	Timeout:                 uint64(30000),
	ChallengeLength:         64,
	AuthenticatorAttachment: webauthn.AuthenticatorCrossPlatform,
	ResidentKey:             webauthn.ResidentKeyPreferred,
	UserVerification:        webauthn.UserVerificationRequired,
	Attestation:             webauthn.AttestationNone,
	CredentialAlgs:          []int{webauthn.COSEAlgES256, webauthn.COSEAlgES384, webauthn.COSEAlgES512, webauthn.COSEAlgRS256},
}

var origin = "https://webauthndemo.ryanjolaughlin.com"

type GenerateChallengeRequest struct {
	Purpose  string `json:"purpose"`
	Username string `json:"username,omitempty"`
}

type Server struct {
	mongoClient mongodb.MongoDB
}

func New() *Server {
	m := mongodb.New()

	return &Server{
		mongoClient: m,
	}
}

// Get Challenge
func (s *Server) GenerateChallenge(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var gcr GenerateChallengeRequest
	err := json.NewDecoder(req.Body).Decode(&gcr)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if gcr.Purpose == "registration" {
		if gcr.Username == "" {
			http.Error(w, "Missing username", http.StatusBadRequest)
			return
		}

		id, err := s.mongoClient.CreateUser(&mongodb.User{
			Username: gcr.Username,
		})

		if err != nil {
			http.Error(w, "Failed to save user", http.StatusBadRequest)
			return
		}

		opts, err := webauthn.NewAttestationOptions(cfg, &webauthn.User{
			Name:        gcr.Username,
			DisplayName: gcr.Username,
			ID:          []byte(id),
		})

		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to generate options %s", err.Error()), http.StatusBadRequest)
			return
		}

		err = s.mongoClient.SaveRegistrationOptions(opts)
		if err != nil {
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to save options %s", err.Error()), http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(opts)
		return
	}

	opts, err := webauthn.NewAssertionOptions(cfg, &webauthn.User{})
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate options %s", err.Error()), http.StatusBadRequest)
		return
	}

	err = s.mongoClient.SaveAuthenticationOptions(opts)
	if err != nil {
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to save options %s", err.Error()), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(opts)
	return
}

// Validate Key
func (s *Server) ValidateKey(w http.ResponseWriter, req *http.Request) {
	assertion, err := webauthn.ParseAssertion(req.Body)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to parse assertion", http.StatusBadRequest)
		return
	}

	storedOpts, err := s.mongoClient.GetRegistrationOptions(assertion.ClientData.Challenge)
	if err != nil {
		http.Error(w, "Failed to get options", http.StatusInternalServerError)
		return
	}

	if storedOpts == nil {
		http.Error(w, "Challenge not found", http.StatusBadRequest)
		return
	}

	user, err := s.mongoClient.GetUserById(string(assertion.UserHandle))
	if err != nil {
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	credID, _ := base64.RawURLEncoding.DecodeString(user.RawPasskey.CredentialID)
	credData, _ := base64.RawURLEncoding.DecodeString(user.RawPasskey.RawCredential)

	credential, _, err := webauthn.ParseCredential(credData)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error parsing credential", http.StatusBadRequest)
		return
	}
	expected := &webauthn.AssertionExpectedData{
		Origin:           origin,
		RPID:             cfg.RPID,
		Challenge:        base64.RawURLEncoding.EncodeToString(storedOpts.Challenge),
		UserVerification: cfg.UserVerification,
		UserID:           assertion.UserHandle,
		UserCredentialIDs: [][]byte{
			credID,
		},
		PrevCounter: uint32(user.RawPasskey.Counter),
		Credential:  credential,
	}

	err = webauthn.VerifyAssertion(assertion, expected)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Invalid assertion", http.StatusBadRequest)
		return
	}

	// increment sign count
	user.RawPasskey.Counter += 1
	s.mongoClient.UpdateUser(string(assertion.UserHandle), user)
	// clean up challenge
	s.mongoClient.DeleteOptions(assertion.ClientData.Challenge)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": user.Username,
	})
}

// Register Key
func (s *Server) RegisterKey(w http.ResponseWriter, req *http.Request) {
	attestation, err := webauthn.ParseAttestation(req.Body)
	if err != nil {
		http.Error(w, "Invalid attestation", http.StatusBadRequest)
		return
	}

	storedOpts, err := s.mongoClient.GetRegistrationOptions(attestation.ClientData.Challenge)
	if err != nil {
		http.Error(w, "Failed to get options", http.StatusInternalServerError)
		return
	}

	if storedOpts == nil {
		http.Error(w, "Challenge not found", http.StatusBadRequest)
		return
	}

	expected := &webauthn.AttestationExpectedData{
		Origin:           origin,
		RPID:             storedOpts.RP.ID,
		CredentialAlgs:   cfg.CredentialAlgs,
		Challenge:        base64.RawURLEncoding.EncodeToString(storedOpts.Challenge),
		UserVerification: cfg.UserVerification,
	}

	attType, trustPath, err := webauthn.VerifyAttestation(attestation, expected)
	if err == nil {
		s.mongoClient.DeleteOptions(attestation.ClientData.Challenge)

		// add to user
		userId := string(storedOpts.User.ID)

		err := s.mongoClient.SavePasskey(userId, attestation.AuthnData)
		if err != nil {
			fmt.Println("error saving passkey: ", err)
			http.Error(w, "Failed to save passkey", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attType":   attType,
		"trustPath": trustPath,
		"err":       err,
	})
	return
}

func main() {
	server := New()
	defer func() {
		if err := server.mongoClient.Client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()

	http.HandleFunc("/api/generate-challenge", server.GenerateChallenge)
	http.HandleFunc("/api/register-key", server.RegisterKey)
	http.HandleFunc("/api/validate-key", server.ValidateKey)
	fmt.Println("Listening on port 3003!")
	http.ListenAndServe(":3003", nil)
}
