// Package loginauth is a plugin that parse user access token and check its validity.
package loginAuth

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"net/http"
	"os"
	"strings"
	"time"
)

type RedisConfig struct {
	Host     string `json:"host"`
	UserName string `json:"username"`
	Password string `json:"password"`
	Db       int    `json:"db,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	Redis            *RedisConfig `json:"redis,omitempty"`
	MaxRequestCount  int          `json:"max_request_count,omitempty"`
	TokenRefreshTime int          `json:"token_refresh_time,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		//	use the free redis lab instance for test only
		Redis: &RedisConfig{
			Host:     "redis-14639.c289.us-west-1-2.ec2.cloud.redislabs.com:14639",
			UserName: "default",
			Password: "AaZd01cOx9vWqxffA3G5Y52l6Im3euGt",
		},
		MaxRequestCount:  100,
		TokenRefreshTime: 3600 * 24, //	refresh token count every day
	}
}

// CheckAccessToken
//  1. check token status from redis sets
//  2. optional token ratelimit
type CheckAccessToken struct {
	next   http.Handler
	name   string
	rdb    *redis.Client
	ctx    context.Context
	config *Config
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Host,
		Password: config.Redis.Password,
		DB:       config.Redis.Db,
	})
	return &CheckAccessToken{
		next:   next,
		name:   name,
		rdb:    rdb,
		ctx:    ctx,
		config: config,
	}, nil
}

func (a *CheckAccessToken) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var path = req.URL.Path
	var path_list = strings.Split(path, "/")
	if len(path_list) < 3 {
		msg := fmt.Sprintf("invalid path, are you using the right middleware? path=%v\n", path)
		fmt.Fprintf(os.Stderr, msg)
		http.Error(rw, msg, http.StatusForbidden)
		return
	}
	token_table_name, token := path_list[1], path_list[2]

	//	update token count
	var status, err = a.updateToken(token, token_table_name)
	if err != nil || status != 200 {
		msg := fmt.Sprintf("CheckAccessToken.updateToken status=%v, err=%v\n", status, err)
		fmt.Fprintf(os.Stderr, msg)
		http.Error(rw, msg, status)
		return
	}

	// pass to next middleware
	a.next.ServeHTTP(rw, req)
}

func (a *CheckAccessToken) updateToken(token, token_table_name string) (int, error) {
	// lua script
	script := `
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local expire = tonumber(ARGV[2])
        local current = redis.call('INCR', key)
        if current == 1 then
            redis.call("EXPIRE", key, expire)
        end
        if current > limit then
            return 429
        else
            return 200
        end
`

	// set timeout
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Second)
	defer cancel()

	//	check whether token table exists
	token_table_exists, err := a.rdb.Exists(a.ctx, token_table_name).Result()
	if err != nil {
		return 500, err
	}
	if token_table_exists == 0 {
		return 404, nil
	}
	//	check whether token in the table
	token_exists, err := a.rdb.SIsMember(a.ctx, token_table_name, token).Result()
	if err != nil {
		return 500, err
	}
	if token_exists == false {
		return 401, nil
	}

	// check token count and update
	if a.config.MaxRequestCount == 0 {
		return 200, nil
	}

	cmd := a.rdb.Eval(
		ctx,
		script,
		[]string{token},
		a.config.MaxRequestCount,
		a.config.TokenRefreshTime,
	)
	status, err := cmd.Result()
	return int(status.(int64)), err
}
