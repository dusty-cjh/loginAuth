package loginAuth_test

import (
	"context"
	"github.com/dusty-cjh/loginAuth"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckAccessToken_ServeHTTP(t *testing.T) {
	cfg := loginAuth.CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := loginAuth.New(ctx, next, cfg, "demo-plugin")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, nil, handler)

	//	init testing redis data
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Host,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.Db,
	})
	rdb.SAdd(ctx, "name_list", "cjh")
	defer func() {
		rdb.Del(ctx, "name_list")
		rdb.Close()
	}()

	var recorder *httptest.ResponseRecorder
	var req *http.Request
	var resp *http.Response
	//	1
	recorder = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	assert.Equal(t, err, nil)
	handler.ServeHTTP(recorder, req)
	resp = recorder.Result()
	assert.Equal(t, 403, resp.StatusCode)

	//	2
	recorder = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/name_list/cjh/123", nil)
	assert.Equal(t, err, nil)
	handler.ServeHTTP(recorder, req)
	resp = recorder.Result()
	assert.Equal(t, 200, resp.StatusCode)

	//	3
	recorder = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/name_list/hd/123", nil)
	assert.Equal(t, err, nil)
	handler.ServeHTTP(recorder, req)
	resp = recorder.Result()
	assert.Equal(t, 401, resp.StatusCode)

}
