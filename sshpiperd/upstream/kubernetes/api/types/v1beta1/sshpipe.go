package v1beta1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type Target struct {
  Name string `json:"name"`
  Port int    `json:"port:omitempty"`
}

type SshPipeSpec struct {
  Users []string `json:"users"`
  Target Target `json:"target"`
}

type SshPipe struct {
  metav1.TypeMeta  `json:",inline"`
  metav1.ObjectMeta `json:"metadata,omitempty"`

  Spec SshPipeSpec `json:"spec"`
}

type SshPipeList struct {
  metav1.TypeMeta `json:",inline"`
  metav1.ListMeta `json:"metadata,omitempty"`

  Items []SshPipe `json:"items"`
}
