package bpf

import (
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

const (
	transformBytes32 = "bytes32"
)

// Configure populates eBPF CollectionSpec variables from a configuration struct.
// It uses reflection to read struct tags in the format `ebpf:"variable_name[,transform]"`
// and sets the corresponding variables in the spec using the ConfigPrefix.
//
// Supported transformations:
//   - bytes32: converts string to [32]byte array
//
// Example:
//
//	type Config struct {
//	    Port uint16 `ebpf:"port"`
//	    Key  string `ebpf:"key,bytes32"`
//	}
func Configure(spec *ebpf.CollectionSpec, cfg interface{}) error {
	if spec == nil {
		return errors.New("spec cannot be nil")
	}
	if cfg == nil {
		return errors.New("config cannot be nil")
	}

	v := reflect.ValueOf(cfg)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return errors.New("config must be a struct or pointer to struct")
	}

	return configureStruct(spec, v)
}

func configureStruct(spec *ebpf.CollectionSpec, v reflect.Value) error {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		tag := field.Tag.Get("ebpf")

		switch fieldValue.Kind() {
		case reflect.Ptr:
			if fieldValue.IsNil() {
				if err := setDefaultsForNilStruct(spec, field.Type.Elem()); err != nil {
					return errors.Wrapf(err, "failed to set defaults for nil %s", field.Name)
				}
				continue
			}
			if err := configureStruct(spec, fieldValue.Elem()); err != nil {
				return errors.Wrapf(err, "failed to configure nested struct %s", field.Name)
			}
			continue
		case reflect.Struct:
			if err := configureStruct(spec, fieldValue); err != nil {
				return errors.Wrapf(err, "failed to configure nested struct %s", field.Name)
			}
			continue
		}

		if tag == "" {
			continue
		}

		name, transform := parseTag(tag)
		valueToSet, err := applyTransform(fieldValue, transform)
		if err != nil {
			return errors.Wrapf(err, "failed to transform field %s", field.Name)
		}

		if err := setVariable(spec, name, reflect.ValueOf(valueToSet)); err != nil {
			return errors.Wrapf(err, "failed to set variable %s", name)
		}
	}

	return nil
}

func parseTag(tag string) (name string, transform string) {
	parts := strings.SplitN(tag, ",", 2)
	name = parts[0]
	if len(parts) > 1 {
		transform = parts[1]
	}
	return
}

func applyTransform(v reflect.Value, transform string) (interface{}, error) {
	switch transform {
	case transformBytes32:
		if v.Kind() != reflect.String {
			return nil, errors.Errorf("bytes32 transform requires string, got %s", v.Kind())
		}
		var arr [32]byte
		copy(arr[:], []byte(v.String()))
		return arr, nil
	case "":
		return v.Interface(), nil
	default:
		return nil, errors.Errorf("unknown transform: %s", transform)
	}
}

func setDefaultsForNilStruct(spec *ebpf.CollectionSpec, structType reflect.Type) error {
	if structType.Kind() != reflect.Struct {
		return nil
	}

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if field.Name == "Enabled" {
			tag := field.Tag.Get("ebpf")
			if tag != "" {
				name, _ := parseTag(tag)
				if err := setVariable(spec, name, reflect.ValueOf(false)); err != nil {
					return errors.Wrapf(err, "failed to set %s to false", name)
				}
				return nil
			}
		}
	}

	return nil
}

// setVariable sets a single variable in the eBPF spec, prepending ConfigPrefix to the name
func setVariable(spec *ebpf.CollectionSpec, name string, value reflect.Value) error {
	// Prepend the config prefix
	fullName := ConfigPrefix + name

	varSpec, exists := spec.Variables[fullName]
	if !exists {
		return errors.Errorf("variable %s not found in spec", fullName)
	}

	// Get the actual value to set
	var val interface{}
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return errors.Errorf("variable %s has nil value", fullName)
		}
		value = value.Elem()
	}
	val = value.Interface()

	if err := varSpec.Set(val); err != nil {
		return errors.Wrapf(err, "failed to set value for variable %s", fullName)
	}

	return nil
}
