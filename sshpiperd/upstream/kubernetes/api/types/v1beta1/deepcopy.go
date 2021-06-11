package v1beta1

import "k8s.io/apimachinery/pkg/runtime"

// DeepCopyInto copies all properties of this object into another object of the
// same type that is provided as a pointer.
func (in *SshPipe) DeepCopyInto(out *SshPipe) {
    out.TypeMeta = in.TypeMeta
    out.ObjectMeta = in.ObjectMeta
    out.Spec = SshPipeSpec{
        Users: in.Spec.Users,
        Target: in.Spec.Target,
    }
}

// DeepCopyObject returns a generically typed copy of an object
func (in *SshPipe) DeepCopyObject() runtime.Object {
    out := SshPipe{}
    in.DeepCopyInto(&out)

    return &out
}

// DeepCopyObject returns a generically typed copy of an object
func (in *SshPipeList) DeepCopyObject() runtime.Object {
    out := SshPipeList{}
    out.TypeMeta = in.TypeMeta
    out.ListMeta = in.ListMeta

    if in.Items != nil {
        out.Items = make([]SshPipe, len(in.Items))
        for i := range in.Items {
            in.Items[i].DeepCopyInto(&out.Items[i])
        }
    }

    return &out
}

