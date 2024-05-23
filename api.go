package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/golang-jwt/jwt/v4"
)

type APIServer struct {
	listenAddr string
	store      Storage
}

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/login", makeHTTPHandleFunc(s.handleLogin))
	router.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHTTPHandleFunc(s.handleGetAccountById), s.store))
	router.HandleFunc("/transfer", makeHTTPHandleFunc(s.handleTransfer))

	log.Println("JSON API server running on port: ", s.listenAddr)

	http.ListenAndServe(s.listenAddr, router)
}

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed")
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	acc, err := s.store.GetAccountByNumber(int(req.Number))
	if err != nil {
		return err
	}

	if err := acc.ValidatePassword(req.Password); err != nil {
		fmt.Errorf("Invalide username or password")
	}

	token, err := createJWT(acc)

	if err != nil {
		return err
	}

	resp := LoginResponse{
		Number: acc.Number,
		Token:  token,
	}

	return WriteJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w, r)
	}

	if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	}

	return fmt.Errorf("method not supported %s", r.Method)
}

func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountById(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w, r)
	}

	if r.Method == "GET" {
		id, err := getId(r)

		if err != nil {
			return err
		}

		account, err := s.store.GetAccountByID(id)

		if err != nil {
			return err
		}

		return WriteJSON(w, http.StatusOK, account)
	}

	return fmt.Errorf("method not supported %s", r.Method)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	request := new(CreateAccountRequest)

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil
	}

	account, err := NewAccount(request.FirstName, request.LastName, request.Password)
	if err != nil {
		return nil
	}

	if err := s.store.CreateAccount(account); err != nil {
		return nil
	}

	return WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getId(r)

	if err != nil {
		return err
	}

	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	transferReq := new(TransferRequest)
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
		return err
	}

	defer r.Body.Close()

	return WriteJSON(w, http.StatusOK, transferReq)
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func sendPermissionDeniedError(w http.ResponseWriter) {
	WriteJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"})
}

func withJWTAuth(handlerFunc http.HandlerFunc, s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT auth middleware")
		tokenString := r.Header.Get("x-jwt-token")
		token, err := validateJWT(tokenString)
		if err != nil {
			fmt.Println("Error getting token")
			sendPermissionDeniedError(w)
			return
		}

		if !token.Valid {
			fmt.Println("Invalid token")
			sendPermissionDeniedError(w)
			return
		}

		userId, err := getId(r)

		if err != nil {
			fmt.Println("No user id exists")
			sendPermissionDeniedError(w)
			return
		}

		account, err := s.GetAccountByID(userId)

		if err != nil {
			fmt.Println("No account exists with id: %d", userId)
			sendPermissionDeniedError(w)
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		if account.Number != int64(claims["accountNumber"].(float64)) {
			fmt.Println("Account number %d does not match with claims %d", account.Number, claims["accountNumber"])
			sendPermissionDeniedError(w)
			return
		}

		handlerFunc(w, r)
	}
}

func createJWT(account *Account) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt":     jwt.NewNumericDate(time.Unix(1516239022, 0)),
		"accountNumber": account.Number,
	}

	secret := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func validateJWT(tokenString string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET")

	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})
}

type apiFunc func(http.ResponseWriter, *http.Request) error
type ApiError struct {
	Error string `json:"error"`
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, ApiError{err.Error()})
		}
	}
}

func getId(r *http.Request) (int, error) {
	idParam := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idParam)

	if err != nil {
		return 0, fmt.Errorf("invaid id given %d", id)
	}

	return id, nil
}
