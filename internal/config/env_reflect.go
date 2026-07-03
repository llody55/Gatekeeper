package config

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// envReflect 通过反射将形如 <PREFIX>_<FIELD> 的环境变量覆盖到结构体字段。
// 支持 string / bool / int / time.Duration / 嵌套 struct。YAML tag 决定子键名。
func envReflect(prefix string, out interface{}) {
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Ptr {
		return
	}
	envStruct(prefix, v.Elem())
}

func envStruct(prefix string, v reflect.Value) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := yamlName(f)
		key := strings.ToUpper(prefix + name)
		fv := v.Field(i)

		switch fv.Kind() {
		case reflect.Struct:
			// 处理 time.Duration 时 fv 是 int64 别名（其实不是 struct），下方 default 兜底
			envStruct(key+"_", fv)
		case reflect.String:
			if val, ok := os.LookupEnv(key); ok {
				fv.SetString(val)
			}
		case reflect.Bool:
			if val, ok := os.LookupEnv(key); ok {
				if b, err := strconv.ParseBool(val); err == nil {
					fv.SetBool(b)
				}
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if fv.Type() == reflect.TypeOf(time.Duration(0)) {
				if val, ok := os.LookupEnv(key); ok {
					if d, err := ParseDuration(val); err == nil {
						fv.SetInt(int64(d))
					}
				}
				continue
			}
			if val, ok := os.LookupEnv(key); ok {
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					fv.SetInt(n)
				}
			}
		case reflect.Slice:
			if fv.Type().Elem().Kind() == reflect.String {
				if val, ok := os.LookupEnv(key); ok {
					parts := strings.Split(val, ",")
					out := make([]string, 0, len(parts))
					for _, p := range parts {
						p = strings.TrimSpace(p)
						if p != "" {
							out = append(out, p)
						}
					}
					fv.Set(reflect.ValueOf(out))
				}
			}
		}
	}
}

func yamlName(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		return f.Name
	}
	// 形如 "listen,omitempty"
	name := strings.SplitN(tag, ",", 2)[0]
	if name == "" || name == "-" {
		return f.Name
	}
	return name
}
