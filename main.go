/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	goflag "flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	meta_util "kmodules.xyz/client-go/meta"
	"kmodules.xyz/client-go/tools/parser"

	flag "github.com/spf13/pflag"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"
)

/*
go run main.go --input=/home/tamal/go/src/k8s.io/api/crds
go run main.go --input=/home/tamal/go/src/k8s.io/kube-aggregator/crds

go run main.go --input=/home/tamal/go/src/github.com/coreos/prometheus-operator/example/prometheus-operator-crd
go run main.go --input=/home/tamal/go/src/github.com/jetstack/cert-manager/deploy/crds
go run main.go --input=/home/tamal/go/src/github.com/appscode/voyager/api/crds
go run main.go --input=/home/tamal/go/src/stash.appscode.dev/apimachinery/crds
go run main.go --input=/home/tamal/go/src/kmodules.xyz/custom-resources/crds
go run main.go --input=/home/tamal/go/src/kubedb.dev/apimachinery/crds
go run main.go --input=/home/tamal/go/src/kubevault.dev/operator/api/crds
go run main.go --input=/home/tamal/go/src/go.searchlight.dev/grafana-operator/crds

go run main.go --input=/home/tamal/go/src/sigs.k8s.io/application/config/crd/bases
*/

var (
	crdstore = map[schema.GroupKind]map[string]*unstructured.Unstructured{}
	empty    = struct{}{}

	allowedGroups = sets.NewString()
	allowedGKs    = map[schema.GroupKind]struct{}{}
)

func main() {
	var input []string
	var out string
	var outputYAML string
	var crdVersion = "v1"
	var gks []string
	var groups []string

	flag.StringSliceVar(&input, "input", input, "List of crd urls or dir/files")
	flag.StringVar(&out, "out", out, "Directory where files to be stored")
	flag.StringVar(&outputYAML, "output-yaml", outputYAML, "Output a single YAML filename")
	flag.StringVar(&crdVersion, "v", crdVersion, "CRD version v1/v1beta1")
	flag.StringSliceVarP(&groups, "group", "g", groups, "List of groups to import")
	flag.StringSliceVar(&gks, "gk", gks, "List of kind.group to import")
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	flag.Parse()

	allowedGroups.Insert(groups...)

	for _, gk := range gks {
		allowedGKs[schema.ParseGroupKind(gk)] = empty
	}

	err := os.MkdirAll(out, 0755)
	if err != nil {
		panic(err)
	}

	for _, location := range input {
		err := processLocation(location)
		if err != nil {
			panic(err)
		}
	}

	var buf bytes.Buffer
	for gk := range crdstore {
		if allowed(gk) {
			data, filename, err := WriteCRD(out, gk, crdVersion)
			if err != nil {
				panic(err)
			}
			if outputYAML != "" {
				if buf.Len() > 0 {
					buf.WriteString("\n---\n")
				}
				buf.Write(data)
			} else {
				err = ioutil.WriteFile(filename, data, 0644)
				if err != nil {
					panic(err)
				}
			}
		}
	}

	if outputYAML != "" {
		err = ioutil.WriteFile(filepath.Join(out, outputYAML), buf.Bytes(), 0644)
		if err != nil {
			panic(err)
		}
	}
}

func allowed(gk schema.GroupKind) bool {
	if len(allowedGroups) == 0 && len(allowedGKs) == 0 {
		return true
	}

	if _, ok := allowedGroups[gk.Group]; ok {
		return true
	}
	if _, ok := allowedGKs[gk]; ok {
		return true
	}
	return false
}

func processLocation(location string) error {
	u, err := url.Parse(location)
	if err != nil {
		return err
	}

	if u.Scheme != "" {
		resp, err := http.Get(u.String())
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		var buf bytes.Buffer
		_, err = io.Copy(&buf, resp.Body)
		if err != nil {
			return err
		}
		return parser.ProcessResources(buf.Bytes(), extractCRD)
	}

	fi, err := os.Stat(location)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return parser.ProcessDir(location, extractCRD)
	} else {
		data, err := ioutil.ReadFile(location)
		if err != nil {
			return err
		}
		return parser.ProcessResources(data, extractCRD)
	}
}

func extractCRD(obj *unstructured.Unstructured) error {
	var def Definition

	err := meta_util.DecodeObject(obj.Object, &def)
	if err != nil {
		return err
	}

	gv, err := schema.ParseGroupVersion(def.APIVersion)
	if err != nil {
		return err
	}

	gk := schema.GroupKind{
		Group: def.Spec.Group,
		Kind:  def.Spec.Names.Kind,
	}

	if _, ok := crdstore[gk]; !ok {
		crdstore[gk] = map[string]*unstructured.Unstructured{}
	}
	crdstore[gk][gv.Version] = obj

	return nil
}

func WriteCRD(dir string, gk schema.GroupKind, version string) ([]byte, string, error) {
	crdversions, ok := crdstore[gk]
	if !ok {
		return nil, "", fmt.Errorf("missing crd for %+v", gk)
	}
	if len(crdversions) == 0 {
		return nil, "", fmt.Errorf("missing crd version for %+v", gk)
	}

	crd, ok := crdversions[version]
	if !ok {
		if version == "v1" {
			// convert to v1
			data, err := yaml.Marshal(crdversions["v1beta1"])
			if err != nil {
				return nil, "", err
			}
			var defv1beta1 crdv1beta1.CustomResourceDefinition
			err = yaml.Unmarshal(data, &defv1beta1)
			if err != nil {
				return nil, "", err
			}

			var inner apiextensions.CustomResourceDefinition
			err = crdv1beta1.Convert_v1beta1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&defv1beta1, &inner, nil)
			if err != nil {
				return nil, "", err
			}

			var defv1 crdv1.CustomResourceDefinition
			err = crdv1.Convert_apiextensions_CustomResourceDefinition_To_v1_CustomResourceDefinition(&inner, &defv1, nil)
			if err != nil {
				return nil, "", err
			}

			data, err = yaml.Marshal(defv1)
			if err != nil {
				return nil, "", err
			}

			filename := filepath.Join(dir, fmt.Sprintf("%s_%s.yaml", defv1.Spec.Group, defv1.Spec.Names.Plural))
			return data, filename, nil
			// return ioutil.WriteFile(filename, data, 0644)
		} else if version == "v1beta1" {
			// convert to v1beta1
			data, err := yaml.Marshal(crdversions["v1"])
			if err != nil {
				return nil, "", err
			}
			var defv1 crdv1.CustomResourceDefinition
			err = yaml.Unmarshal(data, &defv1)
			if err != nil {
				return nil, "", err
			}

			var inner apiextensions.CustomResourceDefinition
			err = crdv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&defv1, &inner, nil)
			if err != nil {
				return nil, "", err
			}

			var defv1beta1 crdv1beta1.CustomResourceDefinition
			err = crdv1beta1.Convert_apiextensions_CustomResourceDefinition_To_v1beta1_CustomResourceDefinition(&inner, &defv1beta1, nil)
			if err != nil {
				return nil, "", err
			}

			data, err = yaml.Marshal(defv1beta1)
			if err != nil {
				return nil, "", err
			}

			filename := filepath.Join(dir, fmt.Sprintf("%s_%s.yaml", defv1beta1.Spec.Group, defv1beta1.Spec.Names.Plural))
			return data, filename, nil
		}
	}

	data, err := yaml.Marshal(crd)
	if err != nil {
		return nil, "", err
	}

	var def Definition
	err = meta_util.DecodeObject(crd.Object, &def)
	if err != nil {
		return nil, "", err
	}
	filename := filepath.Join(dir, fmt.Sprintf("%s_%s.yaml", def.Spec.Group, def.Spec.Names.Plural))
	return data, filename, nil
}
