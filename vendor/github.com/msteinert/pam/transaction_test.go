package pam

import (
	"errors"
	"os/user"
	"runtime"
	"testing"
)

func TestPAM_001(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	p := "secret"
	tx, err := StartFunc("", "test", func(s Style, msg string) (string, error) {
		return p, nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
	err = tx.AcctMgmt(Silent)
	if err != nil {
		t.Fatalf("acct_mgmt #error: %v", err)
	}
	err = tx.SetCred(Silent | EstablishCred)
	if err != nil {
		t.Fatalf("setcred #error: %v", err)
	}
	runtime.GC()
}

func TestPAM_002(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("", "", func(s Style, msg string) (string, error) {
		switch s {
		case PromptEchoOn:
			return "test", nil
		case PromptEchoOff:
			return "secret", nil
		}
		return "", errors.New("unexpected")
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
	runtime.GC()
}

type Credentials struct {
	User     string
	Password string
}

func (c Credentials) RespondPAM(s Style, msg string) (string, error) {
	switch s {
	case PromptEchoOn:
		return c.User, nil
	case PromptEchoOff:
		return c.Password, nil
	}
	return "", errors.New("unexpected")
}

func TestPAM_003(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	c := Credentials{
		User:     "test",
		Password: "secret",
	}
	tx, err := Start("", "", c)
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
	runtime.GC()
}

func TestPAM_004(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	c := Credentials{
		Password: "secret",
	}
	tx, err := Start("", "test", c)
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
	runtime.GC()
}

func TestPAM_005(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("passwd", "test", func(s Style, msg string) (string, error) {
		return "secret", nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.ChangeAuthTok(Silent)
	if err != nil {
		t.Fatalf("chauthtok #error: %v", err)
	}
	runtime.GC()
}

func TestPAM_006(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("passwd", u.Username, func(s Style, msg string) (string, error) {
		return "secret", nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.OpenSession(Silent)
	if err != nil {
		t.Fatalf("open_session #error: %v", err)
	}
	err = tx.CloseSession(Silent)
	if err != nil {
		t.Fatalf("close_session #error: %v", err)
	}
	runtime.GC()
}

func TestPAM_007(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("", "test", func(s Style, msg string) (string, error) {
		return "", errors.New("Sorry, it didn't work")
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err == nil {
		t.Fatalf("authenticate #expected an error")
	}
	s := err.Error()
	if len(s) == 0 {
		t.Fatalf("error #expected an error message")
	}
	runtime.GC()
}

func TestItem(t *testing.T) {
	tx, err := StartFunc("passwd", "test", func(s Style, msg string) (string, error) {
		return "", nil
	})

	s, err := tx.GetItem(Service)
	if err != nil {
		t.Fatalf("getitem #error: %v", err)
	}
	if s != "passwd" {
		t.Fatalf("getitem #error: expected passwd, got %v", s)
	}

	s, err = tx.GetItem(User)
	if err != nil {
		t.Fatalf("getitem #error: %v", err)
	}
	if s != "test" {
		t.Fatalf("getitem #error: expected test, got %v", s)
	}

	err = tx.SetItem(User, "root")
	if err != nil {
		t.Fatalf("setitem #error: %v", err)
	}
	s, err = tx.GetItem(User)
	if err != nil {
		t.Fatalf("getitem #error: %v", err)
	}
	if s != "root" {
		t.Fatalf("getitem #error: expected root, got %v", s)
	}
	runtime.GC()
}

func TestEnv(t *testing.T) {
	tx, err := StartFunc("", "", func(s Style, msg string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}

	m, err := tx.GetEnvList()
	if err != nil {
		t.Fatalf("getenvlist #error: %v", err)
	}
	n := len(m)
	if n != 0 {
		t.Fatalf("putenv #error: expected 0 items, got %v", n)
	}

	vals := []string{
		"VAL1=1",
		"VAL2=2",
		"VAL3=3",
	}
	for _, s := range vals {
		err = tx.PutEnv(s)
		if err != nil {
			t.Fatalf("putenv #error: %v", err)
		}
	}

	s := tx.GetEnv("VAL0")
	if s != "" {
		t.Fatalf("getenv #error: expected \"\", got %v", s)
	}

	s = tx.GetEnv("VAL1")
	if s != "1" {
		t.Fatalf("getenv #error: expected 1, got %v", s)
	}
	s = tx.GetEnv("VAL2")
	if s != "2" {
		t.Fatalf("getenv #error: expected 2, got %v", s)
	}
	s = tx.GetEnv("VAL3")
	if s != "3" {
		t.Fatalf("getenv #error: expected 3, got %v", s)
	}

	m, err = tx.GetEnvList()
	if err != nil {
		t.Fatalf("getenvlist #error: %v", err)
	}
	n = len(m)
	if n != 3 {
		t.Fatalf("getenvlist #error: expected 3 items, got %v", n)
	}
	if m["VAL1"] != "1" {
		t.Fatalf("getenvlist #error: expected 1, got %v", m["VAL1"])
	}
	if m["VAL2"] != "2" {
		t.Fatalf("getenvlist #error: expected 2, got %v", m["VAL1"])
	}
	if m["VAL3"] != "3" {
		t.Fatalf("getenvlist #error: expected 3, got %v", m["VAL1"])
	}
	runtime.GC()
}

func TestFailure_001(t *testing.T) {
	tx := Transaction{}
	_, err := tx.GetEnvList()
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_002(t *testing.T) {
	tx := Transaction{}
	err := tx.PutEnv("")
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_003(t *testing.T) {
	tx := Transaction{}
	err := tx.CloseSession(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_004(t *testing.T) {
	tx := Transaction{}
	err := tx.OpenSession(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_005(t *testing.T) {
	tx := Transaction{}
	err := tx.ChangeAuthTok(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_006(t *testing.T) {
	tx := Transaction{}
	err := tx.AcctMgmt(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_007(t *testing.T) {
	tx := Transaction{}
	err := tx.SetCred(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_008(t *testing.T) {
	tx := Transaction{}
	err := tx.SetItem(User, "test")
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_009(t *testing.T) {
	tx := Transaction{}
	_, err := tx.GetItem(User)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}
