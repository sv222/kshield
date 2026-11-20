package check

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/sv222/kshield/internal/model"
)

const portsField = "ports"

func isGPUDevPath(p string) bool {
	return strings.HasPrefix(p, nvidiaDevPrefix)
}

func wlHostPath(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		var out []Finding
		for i, v := range w.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			if p := path.Clean(v.HostPath.Path); isHostDevPath(p) || isGPUDevPath(p) {
				continue
			}
			msg := fmt.Sprintf("volume %q mounts hostPath %s: the pod reads the node file system (use a PVC, an emptyDir or a CSI volume)", v.Name, v.HostPath.Path)
			out = append(out, violation(w, "", w.SpecPath+"/volumes/"+strconv.Itoa(i), msg))
		}
		return out
	})
}

func wlHostPort(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if c.Init {
			return nil
		}
		var out []Finding
		for i, p := range c.Spec.Ports {
			if p.HostPort == 0 {
				continue
			}
			msg := fmt.Sprintf("port %d is bound to hostPort %d on every node the pod runs on (expose the container through a ClusterIP Service)", p.ContainerPort, p.HostPort)
			out = append(out, violation(w, c.Spec.Name, c.Path+"/"+portsField+"/"+strconv.Itoa(i)+"/hostPort", msg))
		}
		return out
	})
}
