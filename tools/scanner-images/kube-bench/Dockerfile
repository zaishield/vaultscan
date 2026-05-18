FROM aquasec/kube-bench:latest
# DELIBERATELY no USER directive. kube-bench reads
# /etc/kubernetes/* + the kubelet config + container-runtime
# config on the host node — all of which require root. The
# scanner-tool pod that runs this image MUST be allowed to
# runAsNonRoot=false; the chart's per-tool override block in
# scannerWorker.toolOverrides handles this (see chart values
# documentation). Forcing USER 65532 here would silently break
# every kube-bench result.
ENTRYPOINT ["/usr/local/bin/kube-bench"]
