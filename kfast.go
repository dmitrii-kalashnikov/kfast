// kfast v9.5: dynamic summary + label filtering + extended error coverage
//
// Build: go build -o kfast kfast.go
// Run:   ./kfast            |  ./kfast -live  |  ./kfast -live -interval 10s
//
// ENV (labels & widths):
//
//	KFAST_LABELS_EXCLUDE='(^pod-template-hash$|^controller-revision-hash$|^pod-template-generation$)'
//	KFAST_LABELS_INCLUDE='app,version,tier'   # optional allowlist
//
//	KFAST_SUMMARY_NAME_MAX=32
//	KFAST_SUMMARY_REASON_MAX=60
//	KFAST_SUMMARY_NODE_MAX=32
//	KFAST_SUMMARY_LABELS_MAX=80
//	KFAST_SUMMARY_SHOW_INFO=1
//	KFAST_SUMMARY_COLLAPSE_PER_OBJ=1
//
// Other envs (unchanged):
//
//	KFAST_CONCURRENCY=20
//	KFAST_CONTROL_TAG=latest
//	KFAST_REGISTRY_TIMEOUT=8s
//	KFAST_NO_COLOR=1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

/* ===== Config ===== */
var (
	// CLI flags
	liveMode     = flag.Bool("live", false, "Run in live mode with continuous updates")
	liveInterval = flag.Duration("interval", 5*time.Second, "Refresh interval in live mode")
	showHelp     = flag.Bool("help", false, "Show help")

	// Timeouts and limits
	pendingAge      = 3 * time.Minute
	callTimeout     = 10 * time.Second                                              // Per kubectl call timeout
	overallTimeout  = 30 * time.Second                                              // Whole-scan timeout
	prevLogTail     = 10                                                            // Previous logs tail size
	registryTimeout = envDurationOrDefault("KFAST_REGISTRY_TIMEOUT", 4*time.Second) // Registry probe timeout

	// presentation
	showFullPodName = false
	maxEventLine    = 180
	maxLogLine      = 120

	// Summary caps (env-tunable; renderer sizes dynamically up to these)
	summaryNameMax   = envIntOrDefault("KFAST_SUMMARY_NAME_MAX", 30)
	summaryReasonMax = envIntOrDefault("KFAST_SUMMARY_REASON_MAX", 60)
	summaryNodeMax   = envIntOrDefault("KFAST_SUMMARY_NODE_MAX", 32)
	summaryLabelsMax = envIntOrDefault("KFAST_SUMMARY_LABELS_MAX", 80)
	summaryShowInfo  = os.Getenv("KFAST_SUMMARY_SHOW_INFO") != ""
	summaryCollapse  = envBoolOrDefault("KFAST_SUMMARY_COLLAPSE_PER_OBJ", true)

	// Label filtering
	labelsExcludeRe = compileRegexFromEnv("KFAST_LABELS_EXCLUDE",
		"(^pod-template-hash$|^controller-revision-hash$|^pod-template-generation$)")
	labelsIncludeSet = parseSetFromEnv("KFAST_LABELS_INCLUDE") // empty = include all

	CRIT, WARN, INFO = "CRITICAL", "WARNING", "INFO"
)

/* ===== Colors ===== */
var (
	noColor  = os.Getenv("KFAST_NO_COLOR") != ""
	colRed   = colorize("\033[31m")
	colYel   = colorize("\033[33m")
	colGrn   = colorize("\033[32m")
	colCyn   = colorize("\033[36m")
	colMag   = colorize("\033[35m")
	colBlue  = colorize("\033[34m")
	colDim   = colorize("\033[2m")
	colBold  = colorize("\033[1m")
	colReset = colorize("\033[0m")
)

func colorize(s string) string {
	if noColor {
		return ""
	}
	return s
}

/* ===== K8s types ===== */
type OwnerReference struct{ Kind, Name string }

type ObjectMeta struct {
	Name, Namespace, CreationTimestamp string
	OwnerReferences                    []OwnerReference
	Labels                             map[string]string
}

type Condition struct {
	Type, Status, Reason, Message string
	LastTransitionTime            string
}

type Terminated struct {
	Reason     string `json:"reason"`
	ExitCode   int    `json:"exitCode"`
	Message    string `json:"message"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
}
type Running struct {
	StartedAt string `json:"startedAt"`
}
type Waiting struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}
type State struct {
	Waiting    *Waiting    `json:"waiting,omitempty"`
	Running    *Running    `json:"running,omitempty"`
	Terminated *Terminated `json:"terminated,omitempty"`
}
type LastState struct {
	Terminated *Terminated `json:"terminated,omitempty"`
}
type CS struct {
	Name         string    `json:"name"`
	RestartCount int       `json:"restartCount"`
	State        State     `json:"state"`
	LastState    LastState `json:"lastState"`
	Ready        bool      `json:"ready"`
}

type PodStatus struct {
	Phase                 string      `json:"phase"`
	Message               string      `json:"message"`
	StartTime             string      `json:"startTime"`
	ContainerStatuses     []CS        `json:"containerStatuses"`
	InitContainerStatuses []CS        `json:"initContainerStatuses"`
	Conditions            []Condition `json:"conditions"`
	PodIP                 string      `json:"podIP"`
	HostIP                string      `json:"hostIP"`
}
type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   PodStatus  `json:"status"`
	Spec     struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
}
type PodList struct {
	Items []Pod `json:"items"`
}

type Event struct {
	InvolvedObject                struct{ Namespace, Name, Kind string } `json:"involvedObject"`
	Reason, Message, Type         string
	FirstTimestamp, LastTimestamp string
	Count                         int
}
type EventList struct {
	Items []Event `json:"items"`
}

type EndpointsSubset struct {
	Addresses []struct {
		IP string `json:"ip"`
	} `json:"addresses"`
	NotReadyAddresses []struct {
		IP string `json:"ip"`
	} `json:"notReadyAddresses"`
}
type Endpoints struct {
	Metadata ObjectMeta        `json:"metadata"`
	Subsets  []EndpointsSubset `json:"subsets"`
}
type EndpointsList struct {
	Items []Endpoints `json:"items"`
}

type ServiceSpec struct {
	Type     string            `json:"type"`
	Selector map[string]string `json:"selector"`
	Ports    []struct {
		Name       string      `json:"name"`
		Port       int         `json:"port"`
		TargetPort interface{} `json:"targetPort"`
		Protocol   string      `json:"protocol"`
	} `json:"ports"`
}
type Service struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     ServiceSpec `json:"spec"`
}
type ServiceList struct {
	Items []Service `json:"items"`
}

type KObj struct {
	Metadata ObjectMeta `json:"metadata"`
}

type Node struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   struct {
		Conditions []Condition `json:"conditions"`
	} `json:"status"`
}
type NodeList struct {
	Items []Node `json:"items"`
}

/* ===== Finding row ===== */
type Row struct {
	Sev, Type, NS, Name, OwnerKind, OwnerName, Ctr, Reason, Root, Hint string
	Restarts, Exit                                                     int
	Node                                                               string
	Labels                                                             string
	Events                                                             []Event
	LogPrev, LogCurrent                                                string
	Diag                                                               []string
	Fix                                                                []string
	LastSeen                                                           time.Time
	Severity                                                           int // 1=CRIT, 2=WARN, 3=INFO
}

/* ===== Globals ===== */
var (
	evCache      sync.Map
	ownerCache   sync.Map
	resultsMutex sync.RWMutex
	prevResults  []Row
	isFirstRun   = true

	workerLimit = func() int {
		if v := os.Getenv("KFAST_CONCURRENCY"); v != "" {
			if i, err := strconv.Atoi(v); err == nil && i > 0 {
				return i
			}
		}
		return runtime.NumCPU() * 2
	}()
)

/* ================== main ================== */

func main() {
	flag.Parse()
	if *showHelp {
		showUsage()
		return
	}
	if *liveMode {
		runLiveMode()
	} else {
		runOnceMode()
	}
}

/* ============= Fix Generators (existing + new) ============= */

func generateCrashLoopFix(exitCode int, crashReason string) []string {
	base := []string{
		"1. Check container logs: kubectl logs <pod> -c <container> --previous",
		"2. Verify application configuration and environment variables",
		"3. Test application startup locally with same config",
	}
	switch exitCode {
	case 0:
		return append(base, "4. Exit 0 suggests successful completion - check if app should run continuously")
	case 1:
		return append(base, "4. Exit 1 indicates general application error - review logs for specifics")
	case 2:
		return append(base, "4. Exit 2 suggests configuration or usage error")
	case 137:
		return append(base, "4. Exit 137 (SIGKILL) - likely OOMKilled, increase memory limits")
	case 143:
		return append(base, "4. Exit 143 (SIGTERM) - check liveness probe configuration")
	default:
		return append(base, fmt.Sprintf("4. Exit %d - check application documentation for error codes", exitCode))
	}
}

func generateContainerConfigFix(message string, events []Event) []string {
	lower := strings.ToLower(message + " " + joinEventMessages(events))
	if strings.Contains(lower, "secret") && strings.Contains(lower, "not found") {
		return []string{
			"1. Secret not found - create missing secret",
			"2. Check secret name in pod spec matches existing secret",
			"3. Verify secret is in same namespace as pod",
			"4. Create secret: kubectl create secret generic <name> --from-literal=key=value",
		}
	}
	if strings.Contains(lower, "configmap") && strings.Contains(lower, "not found") {
		return []string{
			"1. ConfigMap not found - create missing configMap",
			"2. Check configMap name in pod spec",
			"3. Verify configMap is in same namespace",
			"4. Create configMap: kubectl create configmap <name> --from-file=<path>",
		}
	}
	if strings.Contains(lower, "volume") {
		return []string{
			"1. Volume configuration error detected",
			"2. Check volume definitions in pod spec",
			"3. Verify PVCs exist and are bound",
			"4. Check volume mount paths don't conflict",
		}
	}
	return []string{
		"1. Container configuration error - check pod spec",
		"2. Verify all referenced secrets and configMaps exist",
		"3. Check environment variable references",
		"4. Validate volume mounts and security context",
	}
}

func generateContainerCannotRunFix(message string) []string {
	lower := strings.ToLower(message)
	if strings.Contains(lower, "executable file not found") || strings.Contains(lower, "no such file") {
		return []string{"1. Executable not found in container", "2. Check command/args in container spec", "3. Verify binary exists in container image", "4. Use full path to executable"}
	}
	if strings.Contains(lower, "permission denied") {
		return []string{"1. Permission denied running container command", "2. Check runAsUser in securityContext", "3. Verify execute permissions on binary", "4. For non-root: ensure binary has correct ownership"}
	}
	return []string{"1. Container failed to execute command", "2. Verify command syntax and binary existence", "3. Check container image includes required binaries", "4. Test command locally in same container image"}
}

func generateServiceFix(svc Service) []string {
	fix := []string{"1. Service has no backend pods", "2. Check selector matches pod labels:"}
	if len(svc.Spec.Selector) > 0 {
		fix = append(fix, fmt.Sprintf("   Selector: %v", svc.Spec.Selector), "3. List pods with matching labels: kubectl get pods -l <selector>")
	} else {
		fix = append(fix, "   No selector defined!", "3. Add selector to service spec")
	}
	return append(fix, "4. Create pods with matching labels", "5. Or update service selector to match existing pods")
}

func generateServiceReadinessFix(svc Service) []string {
	fix := []string{
		"1. Service has pods but none are ready",
		"2. Check pod readiness probes:",
		"   kubectl describe pods -l <selector>",
		"3. Common readiness issues:",
		"   - Wrong port in readiness probe",
		"   - Application takes too long to start",
		"   - Readiness endpoint returns non-2xx",
	}
	if len(svc.Spec.Ports) > 0 {
		fix = append(fix, fmt.Sprintf("4. Verify service port %d matches container port", svc.Spec.Ports[0].Port))
	}
	return fix
}

func generateOOMFix() []string {
	return []string{
		"1. Container killed due to out of memory (OOM)",
		"2. Increase memory limits in container spec",
		"3. Check current usage: kubectl top pods",
		"4. Monitor with: kubectl exec <pod> -- ps aux",
		"5. Consider memory leak investigation",
		"6. Optimize application memory usage",
	}
}

func generateInitContainerFix(containerName string, exitCode int) []string {
	return []string{
		fmt.Sprintf("1. Init container '%s' failing (exit %d)", containerName, exitCode),
		"2. Init containers must complete successfully before main containers start",
		"3. Check init container logs: kubectl logs <pod> -c " + containerName,
		"4. Common issues: missing dependencies, network connectivity",
		"5. Ensure init container has proper resource limits",
	}
}

func generateRestartLoopFix(restarts int) []string {
	return []string{
		fmt.Sprintf("1. Container has restarted %d times", restarts),
		"2. High restart count indicates instability",
		"3. Check for:",
		"   - Memory leaks causing OOM kills",
		"   - Liveness probe failures",
		"   - Application crashes",
		"4. Review restart policy (default: Always)",
		"5. Consider increasing probe timeouts",
	}
}

func generateNotReadyFix(conditions []Condition) []string {
	fix := []string{"1. Pod readiness check failing", "2. Check readiness probe configuration"}
	for _, cond := range conditions {
		if cond.Type == "Ready" && cond.Status == "False" && cond.Reason != "" {
			fix = append(fix, fmt.Sprintf("3. Reason: %s", cond.Reason))
			if cond.Message != "" {
				fix = append(fix, fmt.Sprintf("   Message: %s", cond.Message))
			}
		}
	}
	return append(fix, "4. Common fixes:", "   - Adjust readiness probe path/port", "   - Increase initialDelaySeconds", "   - Check application startup time", "   - Verify readiness endpoint health")
}

// --- NEW fix generators covering kubelet/runtime/CNI/registry edge cases ---

func generateRunContainerErrorFix(message string, events []Event) []string {
	l := strings.ToLower(message + " " + joinEventMessages(events))
	steps := []string{
		"1. Container failed at runtime (RunContainerError)",
		"2. Check container command/args and entrypoint",
		"3. Inspect previous logs: kubectl logs <pod> -c <ctr> --previous",
		"4. Verify image architecture matches node (linux/amd64 vs arm64)",
	}
	if strings.Contains(l, "permission") {
		steps = append(steps,
			"5. Permission issue: review securityContext (runAsUser, fsGroup, readOnlyRootFilesystem)",
			"6. Check volume mount ownership/permissions",
		)
	}
	if strings.Contains(l, "no such file") || strings.Contains(l, "not found") {
		steps = append(steps,
			"5. Binary/script missing: verify image contents and PATH",
			"6. Use full path to binary in command",
		)
	}
	return steps
}

func generateKillContainerErrorFix(message string) []string {
	return []string{
		"1. Container was forcibly terminated (KillContainerError)",
		"2. Check for OOM events, liveness probe failures, or app handling of SIGTERM/SIGKILL",
		"3. Review resource limits and probe timeouts",
		"4. Inspect node/kubelet logs around the kill timestamp",
	}
}

func generateVerifyNonRootFix(message string) []string {
	return []string{
		"1. Pod requires non-root (VerifyNonRootError)",
		"2. Set securityContext: runAsNonRoot: true and a non-root runAsUser (e.g., 1000)",
		"3. Ensure image USER is non-root or override with runAsUser",
		"4. Fix file ownership/permissions for mounted paths",
	}
}

func generatePodSandboxFix(reason, message string) []string {
	return []string{
		fmt.Sprintf("1. %s: Pod sandbox lifecycle error (CRI)", reason),
		"2. Check container runtime & kubelet logs on the node",
		"3. Verify cgroups/CRI socket correctness and disk space on /var/lib",
		"4. If using dockershim/CRI-O/containerd: confirm versions and configs",
		"5. Look for CNI errors as these often cascade into sandbox failures",
	}
}

func generateCniFix(reason, message string) []string {
	return []string{
		fmt.Sprintf("1. %s: CNI network setup/teardown failed", reason),
		"2. Check /etc/cni/net.d/*.conf on node; ensure correct CNI plugin is installed",
		"3. Inspect node logs: journalctl -u kubelet, container runtime logs",
		"4. Validate IPAM and routes; ensure node has outbound connectivity",
		"5. If Calico/Flannel/Cilium: verify DaemonSet pods are Running/Ready",
	}
}

func generateImageNeverPullFix() []string {
	return []string{
		"1. imagePullPolicy=Never prevents pulling (ErrImageNeverPull)",
		"2. Push image to a registry or set imagePullPolicy: IfNotPresent/Always",
		"3. For local-only images, ensure they exist on every node",
	}
}

func generateInvalidImageNameFix() []string {
	return []string{
		"1. Invalid image name / reference format",
		"2. Use <registry>/<repo>/<image>:<tag> (tag optional = latest)",
		"3. Avoid spaces/uppercase/invalid characters; underscores are not allowed in the registry host",
		"4. Example: ghcr.io/org/app:1.2.3 or docker.io/library/nginx:1.25",
	}
}

func generateImageInspectFix() []string {
	return []string{
		"1. Image inspect error reported by kubelet/container runtime",
		"2. Validate the image exists: crane manifest <image> (or docker/skopeo)",
		"3. Check registry auth and network connectivity",
		"4. Ensure the image platform matches node architecture",
	}
}

func generateRegistryUnavailableFix() []string {
	return []string{
		"1. Registry unreachable (RegistryUnavailable)",
		"2. From a debug pod: nslookup <registry> && nc -zv <registry> 443",
		"3. Check egress policies, proxies, and corporate firewalls",
		"4. Consider using a registry mirror/cache; verify TLS/CA trust",
	}
}

/* ============= Utility ============= */

func getDisplayName(r Row) string {
	if !showFullPodName && r.OwnerKind != "" && r.OwnerName != "" && r.Type == "Pod" {
		short := extractPodSuffix(r.Name)
		return fmt.Sprintf("%s/%s (%s)", r.OwnerKind, r.OwnerName, short)
	}
	return r.Name
}

func extractPodSuffix(podName string) string {
	parts := strings.Split(podName, "-")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return podName
}

func buildMetadataLine(r Row) string {
	var parts []string
	if r.Ctr != "" {
		parts = append(parts, "container="+r.Ctr)
	}
	if r.Restarts > 0 {
		parts = append(parts, fmt.Sprintf("restarts=%d", r.Restarts))
	}
	if r.Exit != 0 {
		parts = append(parts, fmt.Sprintf("exit=%d", r.Exit))
	}
	return strings.Join(parts, " • ")
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if maxLen <= 0 {
		return s
	}
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

/* ===== env helpers for label filters ===== */

func parseSetFromEnv(key string) map[string]struct{} {
	out := map[string]struct{}{}
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return out
	}
	for _, s := range strings.Split(raw, ",") {
		k := strings.TrimSpace(s)
		if k != "" {
			out[k] = struct{}{}
		}
	}
	return out
}

func compileRegexFromEnv(key, def string) *regexp.Regexp {
	pat := envOrDefault(key, def)
	re, err := regexp.Compile(pat)
	if err != nil {
		// fallback to "match nothing" if bad regex is supplied
		return regexp.MustCompile("^$")
	}
	return re
}

/* ===== label filtering + rendering ===== */

func filterLabelMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	res := make(map[string]string, len(m))
	for k, v := range m {
		if len(labelsIncludeSet) > 0 {
			if _, ok := labelsIncludeSet[k]; !ok {
				continue
			}
		}
		if labelsExcludeRe != nil && labelsExcludeRe.MatchString(k) {
			continue
		}
		res[k] = v
	}
	return res
}

func compactLabels(m map[string]string) string {
	f := filterLabelMap(m)
	if len(f) == 0 {
		return ""
	}
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, f[k]))
	}
	return strings.Join(parts, ",")
}

func nonEmptyLines(text string, limit int) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if limit > 0 && len(lines) > limit {
		return lines[len(lines)-limit:]
	}
	return lines
}

func showUsage() {
	fmt.Printf(`%skfast v9.5%s - Kubernetes Fast Troubleshooting Tool

%sUSAGE:%s
  kfast                      # One-shot analysis
  kfast -live               # Live mode with continuous updates
  kfast -live -interval 10s # Live mode with custom refresh interval
  kfast -help               # Show this help

%sLABEL FILTERING:%s
  KFAST_LABELS_EXCLUDE='(^pod-template-hash$|^controller-revision-hash$|^pod-template-generation$)'
  KFAST_LABELS_INCLUDE='app,version,tier'

%sSUMMARY WIDTH CAPS (auto-sized up to these):%s
  KFAST_SUMMARY_NAME_MAX=32
  KFAST_SUMMARY_REASON_MAX=60
  KFAST_SUMMARY_NODE_MAX=32
  KFAST_SUMMARY_LABELS_MAX=80
  KFAST_SUMMARY_SHOW_INFO=1
  KFAST_SUMMARY_COLLAPSE_PER_OBJ=1
`, colCyn+colBold, colReset, colBold, colReset, colBold, colReset, colBold, colReset)
}

/* ================== runners ================== */

func runOnceMode() {
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	defer cancel()
	results := performScan(ctx)
	displayResults(results, false)
}

func runLiveMode() {
	fmt.Printf("%s🚀 Starting Live Mode%s (refresh every %v, press Ctrl+C to exit)\n",
		colCyn+colBold, colReset, *liveInterval)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*liveInterval)
	defer ticker.Stop()

	// Initial scan
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	results := performScan(ctx)
	cancel()
	displayResults(results, true)

	for {
		select {
		case <-sigChan:
			fmt.Printf("\n%s💡 Live mode stopped%s\n", colDim, colReset)
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
			results := performScan(ctx)
			cancel()
			displayResults(results, true)
		}
	}
}

/* ================== scanning ================== */

func performScan(ctx context.Context) []Row {
	startTime := time.Now()

	if *liveMode && isFirstRun {
		fmt.Print("\033[2J\033[H")
		isFirstRun = false
	}
	if !*liveMode || isFirstRun {
		fmt.Printf("%s🔍 Health Scan%s %s\n", colCyn+colBold, colReset, time.Now().Format("15:04:05"))
	}

	// Quick nodes check
	nodes := getNodes(ctx)
	ready, total, nodeIssues := analyzeNodes(nodes)
	if !*liveMode || isFirstRun {
		fmt.Printf("🖥️  Nodes: %s%d ready%s/%d total", colGrn, ready, colReset, total)
		if len(nodeIssues) > 0 {
			fmt.Printf(" %s(%d issues)%s", colRed, len(nodeIssues), colReset)
		}
		fmt.Printf("\n")
	}

	// Parallel fetch
	var pl PodList
	var el EndpointsList
	var sl ServiceList
	var wg sync.WaitGroup

	wg.Add(3)
	go func() { defer wg.Done(); pl = getPods(ctx) }()
	go func() { defer wg.Done(); el = getEndpoints(ctx) }()
	go func() { defer wg.Done(); sl = getServices(ctx) }()
	wg.Wait()

	// Detection pipeline
	var allRows []Row
	allRows = append(allRows, nodeIssues...)
	allRows = append(allRows, detectPods(ctx, pl)...)
	allRows = append(allRows, detectServices(el, sl)...)
	allRows = dedupAndEnrich(allRows)

	elapsed := time.Since(startTime)
	if !*liveMode || isFirstRun {
		fmt.Printf("⚡ Scan completed in %v\n\n", elapsed.Round(time.Millisecond))
	}
	return allRows
}

/* ================== rendering ================== */

func displayResults(rows []Row, isLive bool) {
	if isLive {
		resultsMutex.Lock()
		prevResults = rows
		resultsMutex.Unlock()
	}

	crit, warn, info := 0, 0, 0
	for _, r := range rows {
		switch r.Sev {
		case CRIT:
			crit++
		case WARN:
			warn++
		case INFO:
			info++
		}
	}

	if isLive && !isFirstRun {
		fmt.Print("\033[H")
	}

	fmt.Printf("%s📊 CLUSTER STATUS%s", colBold, colReset)
	if isLive {
		fmt.Printf(" - %s", time.Now().Format("15:04:05"))
	}
	fmt.Printf("\n")

	if crit > 0 {
		fmt.Printf("%s🚨 Critical: %d%s  ", colRed, crit, colReset)
	}
	if warn > 0 {
		fmt.Printf("%s⚠️  Warning: %d%s  ", colYel, warn, colReset)
	}
	if info > 0 {
		fmt.Printf("%s💡 Info: %d%s  ", colBlue, info, colReset)
	}
	if crit == 0 && warn == 0 && info == 0 {
		fmt.Printf("%s✅ All systems healthy%s", colGrn, colReset)
	}
	fmt.Printf("\n\n")

	if len(rows) == 0 {
		if isLive {
			fmt.Printf("%s🎯 No issues detected - monitoring continues...%s\n", colGrn, colReset)
		}
		if isLive {
			fmt.Print("\033[J")
		}
		return
	}

	printGrouped(rows, isLive)
	printSummaryTable(rows)

	if isLive {
		if !isFirstRun {
			fmt.Print("\033[J")
		}
		fmt.Printf("\n%s🔄 Next update in %v...%s\n", colDim, *liveInterval, colReset)
	}
}

func printSummaryTable(rows []Row) {
	// Filter rows we show
	var filtered []Row
	for _, r := range rows {
		if r.Sev == CRIT || r.Sev == WARN || summaryShowInfo {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) == 0 {
		return
	}

	// Optional collapse per object
	if summaryCollapse {
		type key struct{ ns, typ, name string }
		g := map[key]Row{}
		for _, r := range filtered {
			k := key{r.NS, r.Type, r.Name}
			if ex, ok := g[k]; ok {
				if r.Severity < ex.Severity {
					ex.Sev, ex.Severity = r.Sev, r.Severity
				}
				if ex.Reason == "" || len(r.Reason) > len(ex.Reason) {
					ex.Reason = r.Reason
				}
				if r.Restarts > ex.Restarts {
					ex.Restarts = r.Restarts
				}
				if r.Exit != 0 {
					ex.Exit = r.Exit
				}
				if r.LastSeen.After(ex.LastSeen) {
					ex.LastSeen = r.LastSeen
				}
				if ex.Ctr == "" && r.Ctr != "" {
					ex.Ctr = r.Ctr
				}
				if ex.Node == "" && r.Node != "" {
					ex.Node = r.Node
				}
				if len(r.Labels) > len(ex.Labels) {
					ex.Labels = r.Labels
				}
				g[k] = ex
			} else {
				g[k] = r
			}
		}
		filtered = filtered[:0]
		for _, v := range g {
			filtered = append(filtered, v)
		}
	}

	// Sort by severity, ns, kind, name
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Severity != filtered[j].Severity {
			return filtered[i].Severity < filtered[j].Severity
		}
		if filtered[i].NS != filtered[j].NS {
			return filtered[i].NS < filtered[j].NS
		}
		if filtered[i].Type != filtered[j].Type {
			return filtered[i].Type < filtered[j].Type
		}
		return filtered[i].Name < filtered[j].Name
	})

	// ----- Column headers (AGE removed) -----
	headerNS, headerKind, headerName := "NAMESPACE", "KIND", "NAME"
	headerStatus, headerReason, headerRX := "STATUS", "REASON", "RESTARTS/EXIT"
	headerNode, headerLabels := "NODE", "LABELS"

	// ----- Measure widths (AGE removed) -----
	nsW, typW := len(headerNS), len(headerKind)
	nameW, stW := len(headerName), len(headerStatus)
	reasonW, rxW := len(headerReason), len(headerRX)
	nodeW, lblW := len(headerNode), len(headerLabels)

	for _, r := range filtered {
		nsW = max(nsW, len(r.NS))
		typW = max(typW, len(r.Type))
		stW = max(stW, len(r.Sev))

		dispName := getDisplayName(r)
		nameW = max(nameW, min(len(dispName), summaryNameMax))

		reason := r.Reason
		if reason == "" {
			reason = r.Root
		}
		if reason == "" {
			reason = "-"
		}
		reasonW = max(reasonW, min(len(reason), summaryReasonMax))

		rx := "-"
		if r.Restarts > 0 || r.Exit != 0 {
			if r.Exit != 0 {
				rx = fmt.Sprintf("%d/%d", r.Restarts, r.Exit)
			} else {
				rx = fmt.Sprintf("%d", r.Restarts)
			}
		}
		rxW = max(rxW, len(rx))

		node := r.Node
		if strings.TrimSpace(node) == "" {
			node = "-"
		}
		nodeW = max(nodeW, min(len(node), summaryNodeMax))

		lbl := r.Labels
		if strings.TrimSpace(lbl) == "" {
			lbl = "-"
		}
		lblW = max(lblW, min(len(lbl), summaryLabelsMax))
	}

	// ----- Header & divider (8 columns, 7 gaps) -----
	fmt.Printf("\n%s%sSUMMARY (short)%s — %d item(s)\n", colBold, colCyn, colReset, len(filtered))
	dividerLen := nsW + typW + nameW + stW + reasonW + rxW + nodeW + lblW + 7*2
	fmt.Println(strings.Repeat("─", min(200, dividerLen)))

	// ANSI-aware widths array
	widths := []int{nsW, typW, nameW, stW, reasonW, rxW, nodeW, lblW}

	// Header row (no color in headers)
	printRowANSI(
		[]string{headerNS, headerKind, headerName, headerStatus, headerReason, headerRX, headerNode, headerLabels},
		widths,
	)
	fmt.Println(strings.Repeat("─", min(200, dividerLen)))

	// Rows (pad using visible width; color only changes the string, not the width)
	for _, r := range filtered {
		name := truncate(getDisplayName(r), nameW)

		reason := r.Reason
		if reason == "" {
			reason = r.Root
		}
		if reason == "" {
			reason = "-"
		}
		reason = truncate(reason, reasonW)

		// color REASON
		reasonColored := colRed + reason + colReset

		// color STATUS
		statusStr := r.Sev
		switch r.Sev {
		case CRIT:
			statusStr = colDim + colRed + r.Sev + colReset
		case WARN:
			statusStr = colYel + r.Sev + colReset
		case INFO:
			statusStr = colBlue + r.Sev + colReset
		default:
			statusStr = colDim + r.Sev + colReset
		}

		// RESTARTS/EXIT
		rx := "-"
		if r.Restarts > 0 || r.Exit != 0 {
			if r.Exit != 0 {
				rx = fmt.Sprintf("%d/%d", r.Restarts, r.Exit)
			} else {
				rx = fmt.Sprintf("%d", r.Restarts)
			}
		}

		// NODE
		node := r.Node
		if strings.TrimSpace(node) == "" {
			node = "-"
		}
		node = truncate(node, nodeW)

		// LABELS
		lbl := r.Labels
		if strings.TrimSpace(lbl) == "" {
			lbl = "-"
		}
		lbl = truncate(lbl, lblW)

		printRowANSI(
			[]string{r.NS, r.Type, name, statusStr, reasonColored, rx, node, lbl},
			widths,
		)
	}
}

/* ============= Detailed list rendering ============= */

func printGrouped(rows []Row, isLive bool) {
	if len(rows) == 0 {
		return
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Severity != rows[j].Severity {
			return rows[i].Severity < rows[j].Severity
		}
		if rows[i].NS != rows[j].NS {
			return rows[i].NS < rows[j].NS
		}
		return rows[i].Name < rows[j].Name
	})

	byNS := map[string][]Row{}
	for _, r := range rows {
		byNS[r.NS] = append(byNS[r.NS], r)
	}

	nsKeys := make([]string, 0, len(byNS))
	for ns := range byNS {
		nsKeys = append(nsKeys, ns)
	}
	sort.Strings(nsKeys)

	for i, ns := range nsKeys {
		if i > 0 {
			fmt.Println()
		}

		nsRows := byNS[ns]
		crit, warn, info := 0, 0, 0
		for _, r := range nsRows {
			switch r.Sev {
			case CRIT:
				crit++
			case WARN:
				warn++
			case INFO:
				info++
			}
		}

		fmt.Printf("%s📁 %s%s", colBold, ns, colReset)
		if crit > 0 {
			fmt.Printf(" %s[%d🚨]%s", colRed, crit, colReset)
		}
		if warn > 0 {
			fmt.Printf(" %s[%d⚠️]%s", colYel, warn, colReset)
		}
		if info > 0 {
			fmt.Printf(" %s[%d💡]%s", colBlue, info, colReset)
		}
		fmt.Printf("\n")
		fmt.Println(strings.Repeat("─", 80))

		for j, r := range nsRows {
			printEnhancedRow(r, isLive)
			if j < len(nsRows)-1 {
				fmt.Println()
			}
		}
	}
}

func printEnhancedRow(r Row, isLive bool) {
	var icon, sevCol string
	switch r.Sev {
	case CRIT:
		icon, sevCol = "🚨", colRed
	case WARN:
		icon, sevCol = "⚠️", colYel
	case INFO:
		icon, sevCol = "💡", colBlue
	default:
		icon, sevCol = "●", colDim
	}

	displayName := getDisplayName(r)
	fmt.Printf("  %s%s %s%s: %s %s→ %s%s%s\n",
		sevCol, icon, colReset, r.Type, displayName, colDim, sevCol, r.Reason, colReset)

	if r.Root != "" {
		fmt.Printf("    %s💭 Root Cause:%s %s%s%s\n", colBold, colReset, colYel, r.Root, colReset)
	}

	meta := buildMetadataLine(r)
	if meta != "" {
		fmt.Printf("    %s%s%s\n", colDim, meta, colReset)
	}
	if r.Node != "" {
		fmt.Printf("    %snode=%s%s\n", colDim, r.Node, colReset)
	}
	if strings.TrimSpace(r.Labels) != "" {
		fmt.Printf("    %slabels=%s%s\n", colDim, r.Labels, colReset)
	}

	if len(r.Fix) > 0 {
		fmt.Printf("    %s🔧 Fix Steps:%s\n", colBold, colReset)
		for _, step := range r.Fix {
			fmt.Printf("      %s\n", step)
		}
	} else if r.Hint != "" {
		fmt.Printf("    %s🔧 Fix:%s %s\n", colBold, colReset, r.Hint)
	}

	if len(r.Diag) > 0 {
		fmt.Printf("    %s🔍 Analysis:%s\n", colBold, colReset)
		for _, d := range r.Diag {
			fmt.Printf("      %s\n", d)
		}
	}

	if len(r.Events) > 0 {
		fmt.Printf("    %s📋 Events:%s\n", colBold, colReset)
		for _, e := range r.Events[:min(len(r.Events), 3)] {
			cleanMsg := cleanEventMessage(r.NS, r.Name, e.Message)
			eventLine := fmt.Sprintf("%s: %s", e.Reason, cleanMsg)
			if e.Count > 1 {
				eventLine += fmt.Sprintf(" (×%d)", e.Count)
			}
			fmt.Printf("      📌 %s\n", truncate(eventLine, maxEventLine))
		}
	}

	if r.LogPrev != "" {
		fmt.Printf("    %s📜 Previous Logs:%s\n", colBold, colReset)
		for _, line := range nonEmptyLines(r.LogPrev, prevLogTail) {
			fmt.Printf("      %s%s%s\n", colDim, truncate(line, maxLogLine), colReset)
		}
	}

	if isLive && r.LogCurrent != "" {
		fmt.Printf("    %s📺 Live Logs:%s\n", colBold, colReset)
		for _, line := range nonEmptyLines(r.LogCurrent, 5) {
			fmt.Printf("      %s%s%s\n", colGrn, truncate(line, maxLogLine), colReset)
		}
	}
}

// ANSI-aware padding helpers (to align colored text)
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func visibleLen(s string) int { return len([]rune(stripANSI(s))) }

func padRightANSI(s string, width int) string {
	if width <= 0 {
		return s
	}
	n := width - visibleLen(s)
	if n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

func printRowANSI(cols []string, widths []int) {
	var b strings.Builder
	for i, c := range cols {
		b.WriteString(padRightANSI(c, widths[i]))
		if i < len(cols)-1 {
			b.WriteString("  ") // 2-space gap between columns
		}
	}
	fmt.Println(b.String())
}

/* ============= Detectors ============= */

func detectPods(ctx context.Context, pl PodList) []Row {
	var out []Row
	var mu sync.Mutex

	sem := make(chan struct{}, workerLimit)
	var wg sync.WaitGroup

	for _, p := range pl.Items {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			ns := p.Metadata.Namespace
			ownerKind, ownerName := getOwner(ctx, ns, p.Metadata.OwnerReferences)

			var rows []Row
			rows = append(rows, detectPending(ctx, p, ownerKind, ownerName)...)
			rows = append(rows, detectContainerIssues(ctx, p, ownerKind, ownerName)...)
			rows = append(rows, detectInitContainerIssues(ctx, p, ownerKind, ownerName)...)
			rows = append(rows, detectOOM(ctx, p, ownerKind, ownerName)...)
			rows = append(rows, detectNotReady(ctx, p, ownerKind, ownerName)...)
			rows = append(rows, detectRestartLoop(ctx, p, ownerKind, ownerName)...)

			for i := range rows {
				if rows[i].Reason == "CrashLoopBackOff" {
					rows[i] = enhanceCrashLoopAnalysis(ctx, rows[i], ns, p.Metadata.Name)
				}
			}

			lbl := compactLabels(p.Metadata.Labels)
			for i := range rows {
				rows[i].Node = p.Spec.NodeName
				rows[i].Labels = lbl
			}

			mu.Lock()
			out = append(out, rows...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func detectServices(el EndpointsList, sl ServiceList) []Row {
	svcMap := make(map[string]Service)
	for _, s := range sl.Items {
		key := s.Metadata.Namespace + "/" + s.Metadata.Name
		svcMap[key] = s
	}

	var rows []Row
	for _, e := range el.Items {
		key := e.Metadata.Namespace + "/" + e.Metadata.Name
		svc, exists := svcMap[key]
		if !exists {
			continue
		}
		if svc.Spec.Type == "ExternalName" {
			continue
		}

		totalAddrs, readyAddrs := 0, 0
		for _, subset := range e.Subsets {
			totalAddrs += len(subset.Addresses) + len(subset.NotReadyAddresses)
			readyAddrs += len(subset.Addresses)
		}
		lbl := compactLabels(svc.Metadata.Labels)

		if totalAddrs == 0 {
			rows = append(rows, Row{
				Sev:      CRIT,
				Type:     "Service",
				NS:       e.Metadata.Namespace,
				Name:     e.Metadata.Name,
				Reason:   "NoEndpoints",
				Root:     "Service has no backend pods",
				Hint:     "Selector mismatch or no pods with matching labels",
				Fix:      generateServiceFix(svc),
				LastSeen: time.Now(),
				Severity: 1,
				Labels:   lbl,
			})
		} else if readyAddrs == 0 {
			rows = append(rows, Row{
				Sev:      WARN,
				Type:     "Service",
				NS:       e.Metadata.Namespace,
				Name:     e.Metadata.Name,
				Reason:   "NoReadyEndpoints",
				Root:     fmt.Sprintf("Service has %d pods but none are ready", totalAddrs),
				Hint:     "Pods exist but readiness checks are failing",
				Fix:      generateServiceReadinessFix(svc),
				LastSeen: time.Now(),
				Severity: 2,
				Labels:   lbl,
			})
		}
	}
	return rows
}

/* ============= Image Pull Analysis (enhanced) ============= */

type RegistryTestResult struct {
	requestedTag string
	repository   string
	errorType    string
	diagnostics  []string
}

func enhancedImagePullAnalysis(events []Event, msg string) (root, hint string, diag []string, fix []string) {
	texts := []string{strings.ToLower(msg)}
	for _, e := range events {
		texts = append(texts, strings.ToLower(e.Message))
	}
	joined := strings.Join(texts, " | ")

	// Fast-path recognizers that often appear as messages rather than reasons
	if strings.Contains(joined, "invalid image name") ||
		strings.Contains(joined, "invalid reference") ||
		strings.Contains(joined, "invalid reference format") {
		return "Invalid image name", "Image reference format is invalid", nil, generateInvalidImageNameFix()
	}
	if strings.Contains(joined, "imageneverpull") || strings.Contains(joined, "imagepullpolicy: never") ||
		strings.Contains(joined, "errimageneverpull") {
		return "imagePullPolicy=Never prevents pulling", "Push the image or change policy", nil, generateImageNeverPullFix()
	}

	// Extract image reference if available
	img := extractImageFromEvents(events)
	if img == "" {
		return "Image pull failed", "Check events for specific error",
			[]string{"No image reference found in events"},
			[]string{"Run: kubectl describe pod <pod-name> for detailed error info"}
	}

	// Non-pulling manifest probe to classify tag/auth/network/TLS
	ctx, cancel := context.WithTimeout(context.Background(), registryTimeout)
	defer cancel()
	testResult := performRegistryTest(ctx, img)
	diag = testResult.diagnostics

	switch testResult.errorType {
	case "tag_not_found":
		return fmt.Sprintf("Image tag '%s' does not exist", testResult.requestedTag),
			"The specified tag was not found in the registry",
			diag, []string{
				fmt.Sprintf("1. Verify tag exists: crane ls %s", testResult.repository),
				"2. Check if you meant a different tag (e.g., latest, stable)",
				"3. If building custom image, ensure it was pushed to registry",
				"4. Fix typos in the Deployment image tag",
			}
	case "auth_required":
		return "Registry authentication failed", "Credentials missing or invalid for private registry",
			diag, []string{
				"1. kubectl create secret docker-registry <name> --docker-server=<registry> --docker-username=<user> --docker-password=<pass>",
				"2. Reference the secret in imagePullSecrets or ServiceAccount",
				"3. For ECR/GCR: ensure node IAM/Workload Identity has pull permissions",
			}
	case "network_issue":
		return "Cannot reach registry", "Network connectivity or DNS resolution failed",
			diag, generateRegistryUnavailableFix()
	case "tls_issue":
		return "TLS/Certificate verification failed", "Registry certificate not trusted",
			diag, []string{
				"1. Add registry CA to node trust store",
				"2. Or configure an insecure registry (not for prod)",
				"3. Verify registry hostname matches certificate",
			}
	case "rate_limited":
		return "Registry rate limit exceeded", "Too many pull requests to registry",
			diag, []string{
				"1. Authenticate to increase rate limits",
				"2. Use imagePullPolicy: IfNotPresent to reduce pulls",
				"3. Use a registry mirror/cache",
			}
	default:
		// Fallback based on joined text
		root, hint = classifyImagePullHeuristic(joined)
		return root, hint, diag, []string{
			"1. Check image name and tag for typos",
			"2. Verify registry credentials and permissions",
			"3. Test connectivity to registry from a debug pod",
			"4. Review recent changes to Deployment image fields",
		}
	}
}

func performRegistryTest(ctx context.Context, imageRef string) RegistryTestResult {
	result := RegistryTestResult{}
	tag, repo := splitImageRef(imageRef)
	result.requestedTag, result.repository = tag, repo
	if repo == "" {
		result.errorType = "invalid_ref"
		result.diagnostics = []string{"Invalid image reference format"}
		return result
	}

	reqOK, reqErr, reqTool := probeImageManifest(ctx, imageRef)
	controlTag := envOrDefault("KFAST_CONTROL_TAG", "latest")
	controlRef := repo + ":" + controlTag

	var ctlOK bool
	var ctlErr, ctlTool string
	if controlRef != imageRef {
		ctlOK, ctlErr, ctlTool = probeImageManifest(ctx, controlRef)
	}

	if reqOK {
		result.diagnostics = append(result.diagnostics, fmt.Sprintf("✅ %s → OK (%s)", imageRef, reqTool))
	} else {
		result.diagnostics = append(result.diagnostics, fmt.Sprintf("❌ %s → %s (%s)", imageRef, briefError(reqErr), reqTool))
	}

	if controlRef != imageRef {
		if ctlOK {
			result.diagnostics = append(result.diagnostics, fmt.Sprintf("✅ %s → OK (%s)", controlRef, ctlTool))
		} else {
			result.diagnostics = append(result.diagnostics, fmt.Sprintf("❌ %s → %s (%s)", controlRef, briefError(ctlErr), ctlTool))
		}
	}

	if reqOK {
		result.errorType = "pull_policy_issue"
		result.diagnostics = append(result.diagnostics, "🔍 Image exists but pull is failing - likely node-level issue")
	} else if controlRef != imageRef && ctlOK {
		result.errorType = "tag_not_found"
		result.diagnostics = append(result.diagnostics, "🎯 Tag issue: control tag works but requested tag fails")
	} else {
		combinedError := strings.ToLower(reqErr + " | " + ctlErr)
		switch {
		case containsAny(combinedError, "denied", "unauthorized", "authentication", "basic auth"):
			result.errorType = "auth_required"
		case containsAny(combinedError, "x509", "certificate", "tls"):
			result.errorType = "tls_issue"
		case containsAny(combinedError, "no such host", "timeout", "dial", "dns", "network"):
			result.errorType = "network_issue"
		case containsAny(combinedError, "rate limit", "too many requests"):
			result.errorType = "rate_limited"
		default:
			result.errorType = "unknown"
		}
		result.diagnostics = append(result.diagnostics, "🔍 Both requested and control tags failed - registry-level issue")
	}

	return result
}

/* ============= Pod detectors ============= */

func detectPending(ctx context.Context, p Pod, ownerKind, ownerName string) []Row {
	if p.Status.Phase != "Pending" {
		return nil
	}
	ns, name := p.Metadata.Namespace, p.Metadata.Name
	now := time.Now().UTC()
	start := parseTime(p.Status.StartTime)
	if start.IsZero() {
		start = parseTime(p.Metadata.CreationTimestamp)
	}
	if start.IsZero() || now.Sub(start) <= pendingAge {
		return nil
	}

	events := getEvents(ctx, ns, name)
	last := latestEventTime(events)

	if hasImagePullEvent(events) {
		root, hint, diag, fix := enhancedImagePullAnalysis(events, "")
		return []Row{{
			Sev:       CRIT,
			Type:      "Pod",
			NS:        ns,
			Name:      name,
			Reason:    "ImagePullBackOff",
			Root:      root,
			Hint:      hint,
			OwnerKind: ownerKind,
			OwnerName: ownerName,
			Events:    events,
			Diag:      diag,
			Fix:       fix,
			LastSeen:  last,
			Severity:  1,
			Labels:    compactLabels(p.Metadata.Labels),
		}}
	}

	root, hint, fix := analyzeSchedulingFailure(events, p)
	return []Row{{
		Sev:       CRIT,
		Type:      "Scheduler",
		NS:        ns,
		Name:      name,
		Reason:    "SchedulingFailed",
		Root:      root,
		Hint:      hint,
		OwnerKind: ownerKind,
		OwnerName: ownerName,
		Events:    events,
		Fix:       fix,
		LastSeen:  last,
		Severity:  1,
		Labels:    compactLabels(p.Metadata.Labels),
	}}
}

func detectContainerIssues(ctx context.Context, p Pod, ownerKind, ownerName string) []Row {
	var rows []Row
	ns, name := p.Metadata.Namespace, p.Metadata.Name

	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Waiting == nil {
			continue
		}
		reason := cs.State.Waiting.Reason
		message := cs.State.Waiting.Message
		events := getEvents(ctx, ns, name)
		last := latestEventTime(events)

		switch reason {
		// Existing coverage
		case "CrashLoopBackOff":
			exit := 0
			crashReason := ""
			if cs.LastState.Terminated != nil {
				exit = cs.LastState.Terminated.ExitCode
				crashReason = cs.LastState.Terminated.Reason
			}
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      fmt.Sprintf("Container crashes repeatedly (exit %d)", exit),
				Hint:      "Application startup or runtime failure",
				Restarts:  cs.RestartCount,
				Exit:      exit,
				OwnerKind: ownerKind,
				OwnerName: ownerName,
				Events:    events,
				Fix:       generateCrashLoopFix(exit, crashReason),
				LastSeen:  last,
				Severity:  1,
				Labels:    compactLabels(p.Metadata.Labels),
			})

		case "ImagePullBackOff", "ErrImagePull", "ImageInspectError", "RegistryUnavailable":
			root, hint, diag, fix := enhancedImagePullAnalysis(events, message)
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      root,
				Hint:      hint,
				Restarts:  cs.RestartCount,
				OwnerKind: ownerKind,
				OwnerName: ownerName,
				Events:    events,
				Diag:      diag,
				Fix:       fix,
				LastSeen:  last,
				Severity:  1,
				Labels:    compactLabels(p.Metadata.Labels),
			})

		case "CreateContainerConfigError", "CreateContainerError":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "Container configuration error",
				Hint:      "Invalid environment variables, volumes, or security context",
				OwnerKind: ownerKind,
				OwnerName: ownerName,
				Events:    events,
				Fix:       generateContainerConfigFix(message, events),
				LastSeen:  last,
				Severity:  1,
				Labels:    compactLabels(p.Metadata.Labels),
			})

		case "ContainerCannotRun":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "Container runtime error",
				Hint:      "Binary not found, permission denied, or invalid command",
				OwnerKind: ownerKind,
				OwnerName: ownerName,
				Events:    events,
				Fix:       generateContainerCannotRunFix(message),
				LastSeen:  last,
				Severity:  1,
				Labels:    compactLabels(p.Metadata.Labels),
			})

		// NEW runtime coverage
		case "RunContainerError":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "Container failed to start/execute at runtime",
				Hint:      "See previous logs and command/entrypoint/settings",
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generateRunContainerErrorFix(message, events),
				LastSeen: last, Severity: 1, Labels: compactLabels(p.Metadata.Labels),
			})

		case "KillContainerError":
			rows = append(rows, Row{
				Sev:       WARN,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "Container was killed unexpectedly",
				Hint:      "Check OOM, probes, or signal handling",
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generateKillContainerErrorFix(message),
				LastSeen: last, Severity: 2, Labels: compactLabels(p.Metadata.Labels),
			})

		case "VerifyNonRootError":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "Container must not run as root",
				Hint:      "Set runAsNonRoot and a non-root UID",
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generateVerifyNonRootFix(message),
				LastSeen: last, Severity: 1, Labels: compactLabels(p.Metadata.Labels),
			})

		case "CreatePodSandboxError", "ConfigPodSandboxError", "KillPodSandboxError":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "Pod sandbox (CRI) error",
				Hint:      "Check container runtime/kubelet; may be CNI-related",
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generatePodSandboxFix(reason, message),
				LastSeen: last, Severity: 1, Labels: compactLabels(p.Metadata.Labels),
			})

		case "SetupNetworkError", "TeardownNetworkError":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "CNI network setup/teardown failed",
				Hint:      "Validate CNI plugin config and node networking",
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generateCniFix(reason, message),
				LastSeen: last, Severity: 1, Labels: compactLabels(p.Metadata.Labels),
			})

		// NEW startup coverage
		case "ErrImageNeverPull":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "imagePullPolicy=Never prevents pulling",
				Hint:      "Push image to registry or change policy",
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generateImageNeverPullFix(),
				LastSeen: last, Severity: 1, Labels: compactLabels(p.Metadata.Labels),
			})

		case "InvalidImageName":
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    reason,
				Root:      "Invalid image reference format",
				Hint:      "Use <registry>/<repo>/<image>:<tag>",
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generateInvalidImageNameFix(),
				LastSeen: last, Severity: 1, Labels: compactLabels(p.Metadata.Labels),
			})
		}
	}
	return rows
}

func detectInitContainerIssues(ctx context.Context, p Pod, ownerKind, ownerName string) []Row {
	var rows []Row
	ns, name := p.Metadata.Namespace, p.Metadata.Name

	for _, cs := range p.Status.InitContainerStatuses {
		if cs.State.Waiting == nil {
			continue
		}
		reason := cs.State.Waiting.Reason
		events := getEvents(ctx, ns, name)
		last := latestEventTime(events)
		if reason == "CrashLoopBackOff" || reason == "Error" || reason == "RunInitContainerError" {
			exit := 0
			if cs.LastState.Terminated != nil {
				exit = cs.LastState.Terminated.ExitCode
			}
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    "InitContainer" + reason,
				Root:      fmt.Sprintf("Init container '%s' failing (exit %d)", cs.Name, exit),
				Hint:      "Init must complete successfully before main containers start",
				Exit:      exit,
				Restarts:  cs.RestartCount,
				OwnerKind: ownerKind, OwnerName: ownerName, Events: events,
				Fix:      generateInitContainerFix(cs.Name, exit),
				LastSeen: last, Severity: 1, Labels: compactLabels(p.Metadata.Labels),
			})
		}
	}
	return rows
}

func detectRestartLoop(ctx context.Context, p Pod, ownerKind, ownerName string) []Row {
	var rows []Row
	ns, name := p.Metadata.Namespace, p.Metadata.Name

	for _, cs := range p.Status.ContainerStatuses {
		if cs.RestartCount > 5 && cs.State.Running != nil {
			events := getEvents(ctx, ns, name)
			last := latestEventTime(events)
			rows = append(rows, Row{
				Sev:       WARN,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    "HighRestarts",
				Root:      fmt.Sprintf("Container has restarted %d times", cs.RestartCount),
				Hint:      "Frequent restarts indicate instability",
				Restarts:  cs.RestartCount,
				OwnerKind: ownerKind,
				OwnerName: ownerName,
				Events:    events,
				Fix:       generateRestartLoopFix(cs.RestartCount),
				LastSeen:  last,
				Severity:  2,
				Labels:    compactLabels(p.Metadata.Labels),
			})
		}
	}
	return rows
}

func detectOOM(ctx context.Context, p Pod, ownerKind, ownerName string) []Row {
	var rows []Row
	ns, name := p.Metadata.Namespace, p.Metadata.Name

	for _, cs := range p.Status.ContainerStatuses {
		if cs.LastState.Terminated != nil && cs.LastState.Terminated.Reason == "OOMKilled" {
			events := getEvents(ctx, ns, name)
			last := latestEventTime(events)
			rows = append(rows, Row{
				Sev:       CRIT,
				Type:      "Pod",
				NS:        ns,
				Name:      name,
				Ctr:       cs.Name,
				Reason:    "OOMKilled",
				Root:      "Container exceeded memory limit",
				Hint:      "Process consumed more memory than allocated",
				Restarts:  cs.RestartCount,
				Exit:      cs.LastState.Terminated.ExitCode,
				OwnerKind: ownerKind,
				OwnerName: ownerName,
				Events:    events,
				Fix:       generateOOMFix(),
				LastSeen:  last,
				Severity:  1,
				Labels:    compactLabels(p.Metadata.Labels),
			})
		}
	}
	return rows
}

func detectNotReady(ctx context.Context, p Pod, ownerKind, ownerName string) []Row {
	if p.Status.Phase != "Running" {
		return nil
	}
	ready := false
	for _, cond := range p.Status.Conditions {
		if cond.Type == "Ready" && cond.Status == "True" {
			ready = true
			break
		}
	}
	if ready {
		return nil
	}

	ns, name := p.Metadata.Namespace, p.Metadata.Name
	events := getEvents(ctx, ns, name)
	last := latestEventTime(events)
	fix := generateNotReadyFix(p.Status.Conditions)

	return []Row{{
		Sev:       WARN,
		Type:      "Pod",
		NS:        ns,
		Name:      name,
		Reason:    "NotReady",
		Root:      "Pod readiness check failing",
		Hint:      "Readiness probe failing or sidecars not ready",
		OwnerKind: ownerKind,
		OwnerName: ownerName,
		Events:    events,
		Fix:       fix,
		LastSeen:  last,
		Severity:  2,
		Labels:    compactLabels(p.Metadata.Labels),
	}}
}

/* ============= Helpers ============= */

func enhanceCrashLoopAnalysis(ctx context.Context, row Row, ns, podName string) Row {
	if row.Ctr != "" {
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		row.LogPrev = getPodLogs(cctx, ns, podName, row.Ctr, true, prevLogTail)
		if *liveMode {
			cctx2, cancel2 := context.WithTimeout(ctx, callTimeout)
			defer cancel2()
			row.LogCurrent = getPodLogs(cctx2, ns, podName, row.Ctr, false, 10)
		}
	}
	if row.LogPrev != "" {
		enhancedFix := analyzeLogsForFix(row.LogPrev, row.Exit)
		if len(enhancedFix) > 0 {
			row.Fix = enhancedFix
		}
	}
	return row
}

func analyzeLogsForFix(logs string, exitCode int) []string {
	lower := strings.ToLower(logs)
	if strings.Contains(lower, "address already in use") || strings.Contains(lower, "bind: address already in use") {
		return []string{"1. Port conflict detected - another process is using the port", "2. Change container port in deployment spec", "3. Or fix hostNetwork/hostPort conflicts", "4. Check for multiple replicas binding to same host port"}
	}
	if strings.Contains(lower, "permission denied") {
		return []string{"1. File permission issue detected", "2. Fix fsGroup in securityContext (e.g., fsGroup: 1000)", "3. Or adjust runAsUser/runAsGroup settings", "4. Verify volume mount permissions and ownership", "5. For init containers, ensure they set correct permissions"}
	}
	if strings.Contains(lower, "no such file or directory") || strings.Contains(lower, "file not found") {
		return []string{"1. Missing file or directory in container", "2. Verify WORKDIR and file paths in Dockerfile", "3. Check configMap/secret mounts are correct", "4. Ensure volume mounts point to existing paths", "5. Validate command/args reference existing binaries"}
	}
	if strings.Contains(lower, "connection refused") && (strings.Contains(lower, "database") || strings.Contains(lower, "sql") || strings.Contains(lower, ":5432") || strings.Contains(lower, ":3306")) {
		return []string{"1. Database connection refused", "2. Verify database service is running and ready", "3. Check connection string/hostname in config", "4. Ensure database port is correct (5432 for PostgreSQL, 3306 for MySQL)", "5. Verify network policies allow database access"}
	}
	if strings.Contains(lower, "connection refused") {
		return []string{"1. Service connection refused", "2. Verify target service is running and ready", "3. Check service name and port in configuration", "4. Test connectivity: kubectl exec -it <pod> -- nc -zv <service> <port>", "5. Review network policies and firewall rules"}
	}
	if strings.Contains(lower, "out of memory") || strings.Contains(lower, "cannot allocate memory") {
		return []string{"1. Application running out of memory", "2. Increase memory limits in deployment", "3. Investigate memory leaks in application", "4. Optimize application memory usage", "5. Consider using memory profiling tools"}
	}
	if strings.Contains(lower, "certificate") && (strings.Contains(lower, "invalid") || strings.Contains(lower, "expired") || strings.Contains(lower, "unknown")) {
		return []string{"1. TLS certificate validation failed", "2. Mount correct CA certificates to /etc/ssl/certs/", "3. Update certificates in base image", "4. For testing only: disable certificate verification", "5. Check certificate expiration dates"}
	}
	switch exitCode {
	case 125:
		return []string{"1. Container failed to start (exit 125)", "2. Check Docker/container runtime configuration", "3. Verify image architecture matches node", "4. Review container command and arguments"}
	case 126:
		return []string{"1. Container command not executable (exit 126)", "2. Verify command has execute permissions", "3. Check if command path is correct", "4. For scripts, ensure proper shebang (#!/bin/bash)"}
	case 127:
		return []string{"1. Container command not found (exit 127)", "2. Verify binary exists in container image", "3. Check PATH environment variable", "4. Use full path to binary in command"}
	case 137:
		return []string{"1. Container killed by SIGKILL (exit 137)", "2. Likely OOMKilled - increase memory limits", "3. Check for resource constraints", "4. Review application memory usage patterns"}
	case 143:
		return []string{"1. Container terminated by SIGTERM (exit 143)", "2. Graceful shutdown - may be expected", "3. If unexpected, check for liveness probe failures", "4. Verify graceful shutdown handling in app"}
	}
	return []string{"1. Review application logs above for specific errors", "2. Check environment variables and configuration", "3. Verify all required secrets and configmaps exist", "4. Test application locally with same configuration", "5. Use kubectl exec to debug running container environment"}
}

func analyzeNodes(nodes NodeList) (ready, total int, issues []Row) {
	total = len(nodes.Items)
	for _, node := range nodes.Items {
		nodeReady := false
		var conditions []Condition
		for _, cond := range node.Status.Conditions {
			if cond.Type == "Ready" && cond.Status == "True" {
				nodeReady = true
			}
			if cond.Status == "True" && (cond.Type == "MemoryPressure" || cond.Type == "DiskPressure" || cond.Type == "PIDPressure") {
				conditions = append(conditions, cond)
			}
		}
		if nodeReady {
			ready++
		} else {
			issues = append(issues, Row{
				Sev:    CRIT,
				Type:   "Node",
				Name:   node.Metadata.Name,
				Reason: "NotReady",
				Root:   "Node is not ready",
				Hint:   "Node failed readiness checks",
				Fix: []string{
					"1. Check node status: kubectl describe node " + node.Metadata.Name,
					"2. Verify kubelet is running on the node",
					"3. Check node resources and disk space",
					"4. Review node logs for errors",
				},
				LastSeen: time.Now(),
				Severity: 1,
				Labels:   compactLabels(node.Metadata.Labels),
			})
		}
		if len(conditions) > 0 {
			for _, cond := range conditions {
				issues = append(issues, Row{
					Sev:    WARN,
					Type:   "Node",
					Name:   node.Metadata.Name,
					Reason: cond.Type,
					Root:   cond.Type + " on node",
					Hint:   "Node experiencing resource pressure",
					Fix: []string{
						fmt.Sprintf("1. %s detected on node %s", cond.Type, node.Metadata.Name),
						"2. Free up resources or add more nodes",
						"3. Check disk usage: kubectl exec -it <debug-pod> -- df -h",
						"4. Monitor resource usage: kubectl top nodes",
					},
					LastSeen: time.Now(),
					Severity: 2,
					Labels:   compactLabels(node.Metadata.Labels),
				})
			}
		}
	}
	return ready, total, issues
}

/* ============= Kubernetes helpers ============= */

func getNodes(ctx context.Context) NodeList {
	var nl NodeList
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "get", "nodes", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nl
	}
	_ = json.Unmarshal(output, &nl)
	return nl
}

func getPods(ctx context.Context) PodList {
	var pl PodList
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "get", "pods", "--all-namespaces", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return pl
	}
	_ = json.Unmarshal(output, &pl)
	return pl
}

func getEndpoints(ctx context.Context) EndpointsList {
	var el EndpointsList
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "get", "endpoints", "--all-namespaces", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return el
	}
	_ = json.Unmarshal(output, &el)
	return el
}

func getServices(ctx context.Context) ServiceList {
	var sl ServiceList
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "get", "services", "--all-namespaces", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return sl
	}
	_ = json.Unmarshal(output, &sl)
	return sl
}

func getEvents(ctx context.Context, ns, objName string) []Event {
	cacheKey := ns + "/" + objName
	if cached, ok := evCache.Load(cacheKey); ok {
		if entry, ok := cached.(map[string]interface{}); ok {
			if timestamp, ok := entry["timestamp"].(time.Time); ok {
				if time.Since(timestamp) < 30*time.Second {
					if events, ok := entry["events"].([]Event); ok {
						return events
					}
				}
			}
		}
	}

	var el EventList
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "kubectl", "get", "events", "-n", ns,
		"--field-selector", "involvedObject.name="+objName,
		"--sort-by=.lastTimestamp", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	if err := json.Unmarshal(output, &el); err != nil {
		return nil
	}

	evCache.Store(cacheKey, map[string]interface{}{"timestamp": time.Now(), "events": el.Items})
	return el.Items
}

func getPodLogs(ctx context.Context, ns, podName, containerName string, previous bool, maxLines int) string {
	args := []string{"logs", "-n", ns, podName}
	if containerName != "" {
		args = append(args, "-c", containerName)
	}
	if previous {
		args = append(args, "--previous")
	}
	if maxLines > 0 {
		args = append(args, "--tail", strconv.Itoa(maxLines))
	}
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func getOwner(ctx context.Context, ns string, owners []OwnerReference) (kind, name string) {
	if len(owners) == 0 {
		return "", ""
	}
	owner := owners[0]
	cacheKey := ns + "/" + owner.Kind + "/" + owner.Name
	if cached, ok := ownerCache.Load(cacheKey); ok {
		if entry, ok := cached.(map[string]interface{}); ok {
			if timestamp, ok := entry["timestamp"].(time.Time); ok && time.Since(timestamp) < 60*time.Second {
				if k, ok := entry["kind"].(string); ok {
					if n, ok := entry["name"].(string); ok {
						return k, n
					}
				}
			}
		}
	}
	rootKind, rootName := findRootOwner(ctx, ns, owner.Kind, owner.Name)
	ownerCache.Store(cacheKey, map[string]interface{}{"timestamp": time.Now(), "kind": rootKind, "name": rootName})
	return rootKind, rootName
}

func findRootOwner(ctx context.Context, ns, kind, name string) (string, string) {
	var cmd *exec.Cmd
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	switch kind {
	case "ReplicaSet":
		cmd = exec.CommandContext(cctx, "kubectl", "get", "rs", name, "-n", ns, "-o", "json")
	case "Job":
		cmd = exec.CommandContext(cctx, "kubectl", "get", "job", name, "-n", ns, "-o", "json")
	default:
		return kind, name
	}
	output, err := cmd.Output()
	if err != nil {
		return kind, name
	}
	var obj KObj
	if err := json.Unmarshal(output, &obj); err != nil {
		return kind, name
	}
	if len(obj.Metadata.OwnerReferences) > 0 {
		owner := obj.Metadata.OwnerReferences[0]
		return findRootOwner(ctx, ns, owner.Kind, owner.Name)
	}
	return kind, name
}

/* ============= Registry probing ============= */

func probeImageManifest(ctx context.Context, imageRef string) (bool, string, string) {
	tools := []struct {
		name string
		cmd  func(context.Context, string) *exec.Cmd
	}{
		{"crane", func(ctx context.Context, img string) *exec.Cmd {
			return exec.CommandContext(ctx, "crane", "manifest", img)
		}},
		{"skopeo", func(ctx context.Context, img string) *exec.Cmd {
			return exec.CommandContext(ctx, "skopeo", "inspect", fmt.Sprintf("docker://%s", img))
		}},
		{"docker", func(ctx context.Context, img string) *exec.Cmd {
			return exec.CommandContext(ctx, "docker", "manifest", "inspect", img)
		}},
	}
	for _, tool := range tools {
		if isCommandAvailable(tool.name) {
			cmd := tool.cmd(ctx, imageRef)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil {
				return true, "", tool.name
			} else {
				errMsg := strings.TrimSpace(stderr.String())
				if errMsg == "" {
					errMsg = err.Error()
				}
				return false, errMsg, tool.name
			}
		}
	}
	return false, "No registry tools available (crane, skopeo, docker)", "none"
}

func isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func splitImageRef(imageRef string) (tag, repository string) {
	if strings.Contains(imageRef, ":") {
		parts := strings.SplitN(imageRef, ":", 2)
		if len(parts) == 2 {
			return parts[1], parts[0]
		}
	}
	return "latest", imageRef
}

func extractRegistry(imageRef string) string {
	parts := strings.SplitN(imageRef, "/", 2)
	if len(parts) == 2 && strings.Contains(parts[0], ".") {
		return parts[0]
	}
	return "docker.io"
}

func extractImageFromEvents(events []Event) string {
	for _, e := range events {
		if strings.Contains(e.Reason, "Pull") {
			re := regexp.MustCompile(`(?:image|Image)[\s"':=]+([^\s"',]+)`)
			if matches := re.FindStringSubmatch(e.Message); len(matches) > 1 {
				return strings.Trim(matches[1], `"'`)
			}
		}
	}
	return ""
}

/* ============= Node / Event / Misc Helpers ============= */

func hasImagePullEvent(events []Event) bool {
	for _, e := range events {
		reason := strings.ToLower(e.Reason)
		msg := strings.ToLower(e.Message)
		if e.Type == "Warning" && (strings.Contains(reason, "pull") ||
			strings.Contains(msg, "pulling image") ||
			strings.Contains(msg, "errimagepull") ||
			strings.Contains(msg, "imagepullbackoff")) {
			return true
		}
	}
	return false
}

func analyzeSchedulingFailure(events []Event, pod Pod) (root, hint string, fix []string) {
	joined := strings.ToLower(joinEventMessages(events))

	switch {
	case strings.Contains(joined, "insufficient") && strings.Contains(joined, "cpu"):
		return "Insufficient CPU resources",
			"Cluster doesn't have enough CPU for pod",
			[]string{
				"1. Add more nodes to cluster",
				"2. Reduce CPU requests in pod spec",
				"3. Scale down other workloads to free CPU",
				"4. Use node affinity to target larger nodes",
			}

	case strings.Contains(joined, "insufficient") && strings.Contains(joined, "memory"):
		return "Insufficient memory resources",
			"Cluster doesn't have enough memory for pod",
			[]string{
				"1. Add more nodes with sufficient memory",
				"2. Reduce memory requests in pod spec",
				"3. Scale down memory-intensive workloads",
				"4. Use memory limits to allow overcommit",
			}

	case strings.Contains(joined, "didn't match pod's node affinity") ||
		strings.Contains(joined, "node(s) didn't match pod's node selector"):
		return "Node affinity/selector mismatch",
			"No nodes match the required node selector or affinity rules",
			[]string{
				"1. Check nodeSelector in pod spec: kubectl get pod " + pod.Metadata.Name + " -o yaml",
				"2. List node labels: kubectl get nodes --show-labels",
				"3. Add required labels to nodes or adjust nodeSelector",
				"4. Review node affinity rules for typos",
			}

	case strings.Contains(joined, "had untolerated taint"):
		return "Untolerated node taints",
			"Nodes have taints that pod cannot tolerate",
			[]string{
				"1. List node taints: kubectl describe nodes",
				"2. Add tolerations to pod spec for required taints",
				"3. Or remove taints from nodes: kubectl taint node <node> <taint>-",
				"4. Common taints: node.kubernetes.io/not-ready, node-role.kubernetes.io/master",
			}

	case strings.Contains(joined, "persistentvolumeclaim") && strings.Contains(joined, "not found"):
		return "PersistentVolumeClaim not found",
			"Pod references a PVC that doesn't exist",
			[]string{
				"1. Create the missing PVC: kubectl apply -f <pvc-spec>",
				"2. Check PVC name in pod spec matches existing PVC",
				"3. Verify PVC is in same namespace as pod",
				"4. Check StorageClass exists: kubectl get storageclass",
			}

	case strings.Contains(joined, "0/") && strings.Contains(joined, "nodes are available"):
		nodeCount := extractNodeCount(joined)
		return fmt.Sprintf("No schedulable nodes (%s total)", nodeCount),
			"All nodes are unschedulable",
			[]string{
				"1. Check node status: kubectl get nodes",
				"2. Uncordon nodes: kubectl uncordon <node-name>",
				"3. Check for resource pressure on nodes",
				"4. Remove taints blocking scheduling",
			}

	default:
		return "Scheduling constraints not met",
			"Pod cannot be scheduled due to constraints",
			[]string{
				"1. Review pod requirements: kubectl describe pod " + pod.Metadata.Name,
				"2. Check cluster capacity: kubectl describe nodes",
				"3. Review resource requests and limits",
				"4. Check for conflicting affinity/anti-affinity rules",
			}
	}
}

func classifyImagePullHeuristic(msg string) (root, hint string) {
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "manifest unknown"):
		return "Image or tag not found", "Image doesn't exist in registry"
	case strings.Contains(msg, "denied") || strings.Contains(msg, "unauthorized"):
		return "Registry authentication failed", "Missing or invalid credentials"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "dial"):
		return "Network connectivity issue", "Cannot reach registry"
	case strings.Contains(msg, "certificate") || strings.Contains(msg, "x509"):
		return "TLS certificate issue", "Certificate verification failed"
	default:
		return "Image pull failed", "Check registry and image reference"
	}
}

func cleanEventMessage(ns, podName, msg string) string {
	msg = strings.ReplaceAll(msg, ns+"/"+podName, "<pod>")
	msg = strings.ReplaceAll(msg, podName, "<pod>")
	return msg
}

func joinEventMessages(events []Event) string {
	var msgs []string
	for _, e := range events {
		msgs = append(msgs, e.Message)
	}
	return strings.Join(msgs, " ")
}

func briefError(err string) string {
	switch {
	case strings.Contains(err, "manifest unknown"):
		return "tag not found"
	case strings.Contains(err, "unauthorized"):
		return "auth required"
	case strings.Contains(err, "timeout"):
		return "timeout"
	case strings.Contains(err, "connection refused"):
		return "connection refused"
	default:
		words := strings.Fields(err)
		if len(words) > 5 {
			return strings.Join(words[:5], " ") + "..."
		}
		return err
	}
}

func containsAny(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

/* ============= Dedup & misc utils ============= */

func dedupAndEnrich(rows []Row) []Row {
	type baseKey struct{ ns, name, reason string }
	m := make(map[baseKey]Row)

	merge := func(a, b Row) Row {
		if b.Severity < a.Severity {
			a.Sev, a.Severity = b.Sev, b.Severity
		}
		if a.Ctr == "" && b.Ctr != "" {
			a.Ctr = b.Ctr
		}
		if b.Restarts > a.Restarts {
			a.Restarts = b.Restarts
		}
		if b.Exit != 0 {
			a.Exit = b.Exit
		}
		if b.Root != "" && (a.Root == "" || len(b.Root) > len(a.Root)) {
			a.Root = b.Root
		}
		if b.Hint != "" && (a.Hint == "" || len(b.Hint) > len(a.Hint)) {
			a.Hint = b.Hint
		}
		if a.OwnerKind == "" && b.OwnerKind != "" {
			a.OwnerKind, a.OwnerName = b.OwnerKind, b.OwnerName
		}
		a.Events = uniqueEvents(append(a.Events, b.Events...))
		a.Diag = uniqueStrings(append(a.Diag, b.Diag...))
		a.Fix = uniqueStrings(append(a.Fix, b.Fix...))
		if b.LastSeen.After(a.LastSeen) {
			a.LastSeen = b.LastSeen
		}
		if a.Node == "" && b.Node != "" {
			a.Node = b.Node
		}
		if len(b.Labels) > len(a.Labels) {
			a.Labels = b.Labels
		}
		return a
	}

	for _, r := range rows {
		k := baseKey{ns: r.NS, name: r.Name, reason: r.Reason}
		if ex, ok := m[k]; ok {
			m[k] = merge(ex, r)
		} else {
			if r.LastSeen.IsZero() && len(r.Events) > 0 {
				r.LastSeen = latestEventTime(r.Events)
			}
			m[k] = r
		}
	}

	out := make([]Row, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok && strings.TrimSpace(s) != "" {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func uniqueEvents(events []Event) []Event {
	seen := make(map[string]Event)
	for _, e := range events {
		key := e.Reason + "|" + e.Message
		if existing, exists := seen[key]; exists {
			if e.Count > existing.Count {
				seen[key] = e
			}
		} else {
			seen[key] = e
		}
	}
	result := make([]Event, 0, len(seen))
	for _, e := range seen {
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastTimestamp > result[j].LastTimestamp
	})
	return result
}

/* ============= Time & env helpers ============= */

func parseTime(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, ts)
	return t
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDurationOrDefault(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func envBoolOrDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func humanShortDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Second:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
}

func latestEventTime(evts []Event) time.Time {
	var best time.Time
	for _, e := range evts {
		if t := parseTime(e.LastTimestamp); !t.IsZero() && t.After(best) {
			best = t
		}
		if t := parseTime(e.FirstTimestamp); !t.IsZero() && t.After(best) {
			best = t
		}
	}
	return best
}

func extractNodeCount(message string) string {
	re := regexp.MustCompile(`(\d+)/(\d+)`)
	if matches := re.FindStringSubmatch(message); len(matches) >= 3 {
		return matches[2]
	}
	re = regexp.MustCompile(`(\d+)`)
	if matches := re.FindStringSubmatch(message); len(matches) >= 2 {
		return matches[1]
	}
	return "unknown"
}
