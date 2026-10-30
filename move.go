package main

// Moving a project from one server to another (deploy.me's moves): the copy
// goes straight between the two servers, as root, so the files of databases
// and containers keep their owners. deploy.me asks for it in order:
//
//	source       sudo forge run move-key      a key for this move, its public half back
//	destination  sudo forge run move-accept   the paths it may write, and that key
//	                                          allowed in for them only, from the source
//	source       sudo forge run move-send     rsync each path over ssh with that key,
//	                                          and the images: docker save into docker load
//	both         sudo forge run move-close    the key and its line gone again
//
// On the destination the key's line in the deploy user's authorized_keys runs
// `sudo -n forge run move-receive <move> "$SSH_ORIGINAL_COMMAND"`, which lets
// through only rsync receiving into the paths move-accept wrote down, and
// `docker load` when it allowed images. Every path is a project folder or a
// Docker volume's data: never the system's.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/system"
)

// movesDir keeps each move's key (source) and manifest (destination), root's only.
var movesDir = "/var/lib/forge/moves"

// moveCopyTimeout bounds one path's copy: tens of gigabytes over a slow link.
const moveCopyTimeout = 12 * time.Hour

var (
	moveIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	movePathChars  = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]+$`)
	moveVolumeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	moveUserName   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	moveKeyLine    = regexp.MustCompile(`^(ssh-ed25519) ([A-Za-z0-9+/]+={0,2})(?: .*)?$`)
	moveHostKey    = regexp.MustCompile(`^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa) ([A-Za-z0-9+/]+={0,2})$`)
	moveAddress    = regexp.MustCompile(`^[A-Za-z0-9.:-]+$`)
	moveOnlyName   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	// rsync's --usermap/--groupmap as a move uses them: numeric IDs only, FROM:TO,…
	moveIDMap     = regexp.MustCompile(`^[0-9]{1,10}:[0-9]{1,10}(?:,[0-9]{1,10}:[0-9]{1,10}){0,7}$`)
	moveImageName = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9._/-]*(?::[0-9]+)?/)?[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$`)
	moveImageID   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// moveImageRef is an image as docker save takes it: a name with its tag, or an image ID.
func moveImageRef(ref string) bool {
	if strings.HasPrefix(ref, "sha256:") {
		return moveImageID.MatchString(ref)
	}
	return moveImageName.MatchString(ref)
}

// moveLoadCommand is what the source's ssh asks the destination to run for the images.
const moveLoadCommand = "docker load"

// System folders a move never reads or writes, nor anything below them.
// /var is the system's too; a Docker volume's data is allowed on its own.
var moveSystemPaths = []string{"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/lost+found", "/proc", "/root", "/run", "/sbin", "/snap", "/sys", "/tmp", "/usr", "/var"}

// moveManifest is what the destination may receive for a move.
type moveManifest struct {
	ID      string    `json:"id"`
	User    string    `json:"user"`
	From    string    `json:"from"`
	Paths   []string  `json:"paths"`
	Images  bool      `json:"images,omitempty"`
	Created time.Time `json:"created"`
}

// dockerRootDir is where Docker keeps its volumes ("/var/lib/docker" unless set).
var dockerRootDir = func() string {
	if out, err := system.Output("docker", "info", "--format", "{{.DockerRootDir}}"); err == nil {
		if dir := strings.TrimSpace(out); filepath.IsAbs(dir) {
			return filepath.Clean(dir)
		}
	}
	return "/var/lib/docker"
}

// movePath checks one path a move reads or writes: a Docker volume's data (or
// a folder in it), or a project folder at least two levels deep outside the
// system's folders. It says which, and for a volume its folder.
func movePath(p, dockerRoot string) (kind, volume string, err error) {
	if !movePathChars.MatchString(p) || filepath.Clean(p) != p || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return "", "", fmt.Errorf("%q isn't a clean absolute path of letters, digits and ._@+-", p)
	}
	volumes := dockerRoot + "/volumes/"
	if rest, ok := strings.CutPrefix(p, volumes); ok {
		parts := strings.Split(rest, "/")
		if len(parts) < 2 || !moveVolumeName.MatchString(parts[0]) || parts[1] != "_data" {
			return "", "", fmt.Errorf("%s: only a volume's _data folder (or below it) moves", p)
		}
		return "volume", volumes + parts[0], nil
	}
	if p == dockerRoot || strings.HasPrefix(p, dockerRoot+"/") {
		return "", "", fmt.Errorf("%s is Docker's own", p)
	}
	for _, sys := range moveSystemPaths {
		if p == sys || strings.HasPrefix(p, sys+"/") {
			return "", "", fmt.Errorf("%s is the system's", p)
		}
	}
	depth := strings.Count(p, "/")
	if depth < 2 || (strings.HasPrefix(p, "/home/") && depth < 3) {
		return "", "", fmt.Errorf("%s is too high up: a project's folder is at least two levels deep, like /srv/projects/app", p)
	}
	return "folder", "", nil
}

func moveID(in map[string]string) (string, error) {
	if !moveIDPattern.MatchString(in["move"]) {
		return "", errors.New("move: lowercase letters, digits and dashes, up to 40")
	}
	return in["move"], nil
}

// moveLines splits a list given one per line (or separated by spaces).
func moveLines(s string) []string {
	return strings.Fields(s)
}

func manifestPath(id string) string { return filepath.Join(movesDir, id+".json") }

func loadManifest(id string) (*moveManifest, error) {
	data, err := os.ReadFile(manifestPath(id))
	if err != nil {
		return nil, err
	}
	var m moveManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func saveManifest(m *moveManifest) error {
	if err := os.MkdirAll(movesDir, 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(m, "", "  ")
	tmp := manifestPath(m.ID) + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, manifestPath(m.ID))
}

// keyMarker ends each authorized_keys line a move adds, so close finds it.
func keyMarker(id string) string { return "forge-move:" + id }

// rewriteAuthorizedKeys drops a move's lines from the user's authorized_keys
// and, given one, adds it; the file keeps its owner and stays 0600.
func rewriteAuthorizedKeys(u *user.User, id, line string) error {
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	dir := filepath.Join(u.HomeDir, ".ssh")
	path := filepath.Join(dir, "authorized_keys")

	var kept []string
	if data, err := os.ReadFile(path); err == nil {
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if l != "" && !strings.HasSuffix(l, " "+keyMarker(id)) {
				kept = append(kept, l)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if line == "" {
		return nil
	}
	if line != "" {
		kept = append(kept, line)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chown(dir, uid, gid)
	tmp := path + ".forge-move"
	body := strings.Join(kept, "\n")
	if body != "" {
		body += "\n"
	}
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	if err := os.Chown(tmp, uid, gid); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// isEmptyDir: a folder with nothing in it.
func isEmptyDir(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := f.Readdirnames(1); errors.Is(err, io.EOF) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	return false, nil
}

// acceptPaths checks what the destination will receive and makes the folders
// that aren't there yet. A folder already holding files is refused unless an
// earlier copy of the same move put them there.
func acceptPaths(paths []string, earlier []string, dockerRoot string) error {
	for _, p := range paths {
		kind, volume, err := movePath(p, dockerRoot)
		if err != nil {
			return err
		}
		if kind == "volume" {
			if info, err := os.Stat(volume + "/_data"); err != nil || !info.IsDir() {
				return fmt.Errorf("%s: the volume %s isn't on this server: make it first", p, filepath.Base(volume))
			}
		}
		info, err := os.Stat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case !info.IsDir():
			return fmt.Errorf("%s is a file, not a folder", p)
		case kind == "folder" && !slices.Contains(earlier, p):
			if empty, err := isEmptyDir(p); err != nil || !empty {
				return fmt.Errorf("%s already holds files: a move goes into an empty folder", p)
			}
		}
	}
	return nil
}

var moveModules = []module{
	{
		Name:        "move-key",
		Title:       "Move: the copy's key",
		Description: "Makes the ssh key this server copies a moving project with, and hands back its public half. Nothing else changes.",
		Internal:    true,
		Inputs:      []moduleInput{{Name: "move", Type: "text", Label: "Move", Required: true}},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			id, err := moveID(in)
			if err != nil {
				return nil, nil, err
			}
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Make the move's key", Run: func(c *steps.Context) error {
				dir := filepath.Join(movesDir, id)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return err
				}
				key := filepath.Join(dir, "key")
				if !system.FileExists(key) {
					if _, err := system.Run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", keyMarker(id), "-f", key); err != nil {
						return err
					}
				}
				pub, err := os.ReadFile(key + ".pub")
				if err != nil {
					return err
				}
				c.Result = map[string]any{"key": strings.TrimSpace(string(pub))}
				return nil
			}}}, ctx, nil
		},
	},
	{
		Name:        "move-accept",
		Title:       "Move: let the copy in",
		Description: "Lets one moving project's copy in: the paths it may write (project folders and Docker volumes only), and its key, from the source's address only, for rsync into those paths and nothing else.",
		Danger:      true,
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "move", Type: "text", Label: "Move", Required: true},
			{Name: "user", Type: "text", Label: "User the copy logs in as", Required: true},
			{Name: "from", Type: "text", Label: "Source address", Required: true},
			{Name: "key", Type: "text", Label: "The copy's public key", Required: true},
			{Name: "paths", Type: "text", Label: "Paths it writes, one per line", Required: true},
			{Name: "images", Type: "choice", Label: "Images too (docker load)", Options: []string{"yes", "no"}},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			id, err := moveID(in)
			if err != nil {
				return nil, nil, err
			}
			if !moveUserName.MatchString(in["user"]) || in["user"] == "root" {
				return nil, nil, errors.New("user: a login name other than root")
			}
			if net.ParseIP(in["from"]) == nil {
				return nil, nil, errors.New("from: the source's IP address")
			}
			key := moveKeyLine.FindStringSubmatch(in["key"])
			if key == nil {
				return nil, nil, errors.New("key: an ssh-ed25519 public key")
			}
			paths := moveLines(in["paths"])
			if len(paths) == 0 {
				return nil, nil, errors.New("paths: at least one")
			}
			ctx := &steps.Context{}
			return []steps.Step{{Name: "Let the copy in", Run: func(c *steps.Context) error {
				u, err := user.Lookup(in["user"])
				if err != nil {
					return fmt.Errorf("no user %s here", in["user"])
				}
				m, err := loadManifest(id)
				if err != nil {
					m = &moveManifest{ID: id, Created: time.Now().UTC()}
				} else if m.User != in["user"] {
					return fmt.Errorf("move %s lets %s in, not %s", id, m.User, in["user"])
				}
				if err := acceptPaths(paths, m.Paths, dockerRootDir()); err != nil {
					return err
				}
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				m.User, m.From = in["user"], in["from"]
				m.Images = m.Images || in["images"] == "yes"
				for _, p := range paths {
					if !slices.Contains(m.Paths, p) {
						m.Paths = append(m.Paths, p)
					}
				}
				if err := saveManifest(m); err != nil {
					return err
				}
				line := fmt.Sprintf(`restrict,from="%s",command="sudo -n %s run move-receive %s \"$SSH_ORIGINAL_COMMAND\"" %s %s %s`,
					in["from"], exe, id, key[1], key[2], keyMarker(id))
				if err := rewriteAuthorizedKeys(u, id, line); err != nil {
					return err
				}
				c.Notes = append(c.Notes, fmt.Sprintf("%s may copy into %d path(s) as %s", in["from"], len(m.Paths), in["user"]))
				return nil
			}}}, ctx, nil
		},
	},
	{
		Name:        "move-send",
		Title:       "Move: copy to the new server",
		Description: "Copies a moving project's folder and volumes to the new server with rsync over ssh, as root, keeping owners and links, and the images its containers run (docker save into docker load there).",
		Danger:      true,
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "move", Type: "text", Label: "Move", Required: true},
			{Name: "to", Type: "text", Label: "Destination address", Required: true},
			{Name: "port", Type: "text", Label: "Its ssh port"},
			{Name: "user", Type: "text", Label: "User there", Required: true},
			{Name: "host_key", Type: "text", Label: "Its host key", Required: true},
			{Name: "pairs", Type: "text", Label: "What goes where: a source path and a destination path per line"},
			{Name: "delete", Type: "choice", Label: "Remove what the source no longer has", Options: []string{"yes", "no"}},
			{Name: "only", Type: "text", Label: "Only these folders one level down in each source, by name (an edge's certificates of one project's hosts)"},
			{Name: "images", Type: "text", Label: "Images to send, by name:tag or ID, one per line"},
			{Name: "usermap", Type: "text", Label: "User IDs that differ there, FROM:TO,… (the deploy user's own files)"},
			{Name: "groupmap", Type: "text", Label: "Group IDs that differ there, FROM:TO,…"},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			id, err := moveID(in)
			if err != nil {
				return nil, nil, err
			}
			if !moveAddress.MatchString(in["to"]) || strings.HasPrefix(in["to"], "-") {
				return nil, nil, errors.New("to: an address or host name")
			}
			port := in["port"]
			if port == "" {
				port = "22"
			}
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, nil, errors.New("port: 1–65535")
			}
			if !moveUserName.MatchString(in["user"]) {
				return nil, nil, errors.New("user: a login name")
			}
			if !moveHostKey.MatchString(in["host_key"]) {
				return nil, nil, errors.New("host_key: the destination's host key, as `type base64`")
			}
			only := moveLines(in["only"])
			for _, name := range only {
				if !moveOnlyName.MatchString(name) {
					return nil, nil, fmt.Errorf("only: %q isn't a host name", name)
				}
			}
			for _, name := range []string{"usermap", "groupmap"} {
				if in[name] != "" && !moveIDMap.MatchString(in[name]) {
					return nil, nil, fmt.Errorf("%s: numeric FROM:TO pairs, comma-separated", name)
				}
			}
			images := moveLines(in["images"])
			for _, ref := range images {
				if !moveImageRef(ref) {
					return nil, nil, fmt.Errorf("images: %q isn't an image name or ID", ref)
				}
			}
			fields := moveLines(in["pairs"])
			if len(fields)%2 != 0 || len(fields) == 0 && len(images) == 0 {
				return nil, nil, errors.New("pairs: a source and a destination path, one pair per line (or images to send)")
			}
			dockerRoot := dockerRootDir()
			for i, p := range fields {
				if _, _, err := movePath(p, dockerRoot); err != nil {
					return nil, nil, err
				}
				if i%2 == 0 {
					if info, err := os.Stat(p); err != nil || !info.IsDir() {
						return nil, nil, fmt.Errorf("%s isn't a folder here", p)
					}
				}
			}

			dir := filepath.Join(movesDir, id)
			key := filepath.Join(dir, "key")
			known := filepath.Join(dir, "known_hosts")
			host := in["to"]
			if port != "22" {
				host = "[" + in["to"] + "]:" + port
			}
			sshArgs := []string{"ssh", "-i", key, "-p", port, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
				"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known, "-o", "ConnectTimeout=20",
				"-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=6"}
			sshCmd := strings.Join(sshArgs, " ")

			ctx := &steps.Context{Result: map[string]any{}}
			st := []steps.Step{{Name: "Trust the new server's host key", Run: func(*steps.Context) error {
				if !system.FileExists(key) {
					return errors.New("this move has no key here: run move-key first")
				}
				return os.WriteFile(known, []byte(host+" "+in["host_key"]+"\n"), 0o600)
			}}}
			for i := 0; i < len(fields); i += 2 {
				src, dst := fields[i], fields[i+1]
				st = append(st, steps.Step{Name: "Copy " + src, Run: func(c *steps.Context) error {
					args := []string{"-aHAX", "--numeric-ids", "--info=progress2", "--stats", "-e", sshCmd}
					if in["delete"] == "yes" {
						args = append(args, "--delete")
					}
					// The deploy user is another ID there: its files stay its own,
					// not some other account's (the copy keeps numeric IDs).
					if in["usermap"] != "" {
						args = append(args, "--usermap="+in["usermap"])
					}
					if in["groupmap"] != "" {
						args = append(args, "--groupmap="+in["groupmap"])
					}
					if len(only) > 0 {
						args = append(args, "--prune-empty-dirs", "--include=/*/")
						for _, name := range only {
							args = append(args, "--include=/*/"+name+"/***")
						}
						args = append(args, "--exclude=*")
					}
					args = append(args, src+"/", in["user"]+"@"+in["to"]+":"+dst+"/")
					out, err := system.RunProgress("rsync "+src+"/ → "+in["to"]+":"+dst+"/", moveCopyTimeout, nil, "rsync", args...)
					var exit *exec.ExitError
					// 24: files vanished while a running source was copied; the next pass takes the rest.
					if errors.As(err, &exit) && exit.ExitCode() == 24 {
						c.Notes = append(c.Notes, src+": some files changed while it was copied")
						err = nil
					}
					if err != nil {
						return err
					}
					c.Result[src] = rsyncStats(out)
					return nil
				}})
			}
			if len(images) > 0 {
				st = append(st, steps.Step{Name: fmt.Sprintf("Copy %d image(s)", len(images)), Run: func(c *steps.Context) error {
					save := append([]string{"docker", "save"}, images...)
					load := append(slices.Clone(sshArgs), in["user"]+"@"+in["to"], moveLoadCommand)
					out, sent, err := system.RunPipe("docker save | "+in["to"]+": docker load", moveCopyTimeout, save, load)
					if err != nil {
						return err
					}
					c.Result["images"] = map[string]any{"sent": sent, "loaded": strings.Count(out, "Loaded image")}
					return nil
				}})
			}
			return st, ctx, nil
		},
	},
	{
		Name:        "move-close",
		Title:       "Move: close the copy's way in",
		Description: "Stops a copy still running with a move's key, removes the key and its line in authorized_keys; with forget, also what the destination was told it may receive.",
		Internal:    true,
		Inputs: []moduleInput{
			{Name: "move", Type: "text", Label: "Move", Required: true},
			{Name: "forget", Type: "choice", Label: "Forget the move here", Options: []string{"yes", "no"}},
		},
		build: func(in map[string]string) ([]steps.Step, *steps.Context, error) {
			id, err := moveID(in)
			if err != nil {
				return nil, nil, err
			}
			return []steps.Step{{Name: "Close the copy's way in", Run: func(*steps.Context) error {
				// A copy deploy.me let go of (a cancel, a timeout) stops here: its
				// rsync is the one whose ssh holds this move's key.
				_ = exec.Command("pkill", "-TERM", "-f", regexp.QuoteMeta(filepath.Join(movesDir, id, "key"))).Run()
				if m, err := loadManifest(id); err == nil {
					if u, err := user.Lookup(m.User); err == nil {
						if err := rewriteAuthorizedKeys(u, id, ""); err != nil {
							return err
						}
					}
					if in["forget"] == "yes" {
						if err := os.Remove(manifestPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
							return err
						}
					}
				}
				return os.RemoveAll(filepath.Join(movesDir, id))
			}}}, &steps.Context{}, nil
		},
	},
}

func init() {
	modules = append(modules, moveModules...)
}

// rsyncStats reads the totals --stats prints.
func rsyncStats(out string) map[string]int64 {
	stats := map[string]int64{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		name, value, ok := strings.Cut(sc.Text(), ": ")
		if !ok {
			continue
		}
		key := map[string]string{"Number of files": "files", "Number of regular files transferred": "transferred", "Total file size": "bytes", "Total transferred file size": "sent"}[name]
		if key == "" {
			continue
		}
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, strings.Fields(value)[0])
		if n, err := strconv.ParseInt(digits, 10, 64); err == nil {
			stats[key] = n
		}
	}
	return stats
}

// rsyncLongOptions are what a sending rsync passes the receiver on its own
// that a move may use; anything else is refused.
var rsyncLongOptions = []string{"--numeric-ids", "--stats", "--delete", "--delete-before", "--delete-during", "--delete-delay", "--delete-after", "--partial", "--inplace", "--sparse"}

var rsyncShortOptions = regexp.MustCompile(`^-[A-Za-z]+(?:\.[A-Za-z]*)?$`)

// moveReceiveArgs checks the command the source's rsync asked ssh to run:
// only a receiving rsync, into a path the manifest lists.
func moveReceiveArgs(command string, m *moveManifest) ([]string, error) {
	args := strings.Fields(command)
	if len(args) < 4 || args[0] != "rsync" || args[1] != "--server" {
		return nil, errors.New("only rsync may come in this way")
	}
	dst, dot := args[len(args)-1], args[len(args)-2]
	if dot != "." {
		return nil, errors.New("one destination path, after \".\"")
	}
	if !slices.Contains(m.Paths, strings.TrimSuffix(dst, "/")) {
		return nil, fmt.Errorf("%s isn't a path this move may write", dst)
	}
	for _, a := range args[2 : len(args)-2] {
		switch {
		case a == "--sender":
			return nil, errors.New("nothing is read from this server")
		case strings.HasPrefix(a, "--usermap=") || strings.HasPrefix(a, "--groupmap="):
			if _, value, _ := strings.Cut(a, "="); !moveIDMap.MatchString(value) {
				return nil, fmt.Errorf("%s isn't allowed", a)
			}
		case strings.HasPrefix(a, "--") && !slices.Contains(rsyncLongOptions, a):
			return nil, fmt.Errorf("%s isn't allowed", a)
		case !strings.HasPrefix(a, "--") && !rsyncShortOptions.MatchString(a):
			return nil, fmt.Errorf("%s isn't allowed", a)
		}
	}
	return args, nil
}

// moveReceive is `forge run move-receive <move> <command>`: what the move's
// key runs on the destination. It becomes the receiving rsync, or refuses.
func moveReceive(args []string) int {
	fail := func(msg string) int {
		fmt.Fprintln(os.Stderr, "forge move-receive: "+msg)
		return 1
	}
	if os.Geteuid() != 0 {
		return fail("needs root")
	}
	if len(args) != 2 || !moveIDPattern.MatchString(args[0]) {
		return fail("usage: forge run move-receive <move> <rsync command>")
	}
	m, err := loadManifest(args[0])
	if err != nil {
		return fail("no move " + args[0] + " here")
	}
	if args[1] == moveLoadCommand {
		if !m.Images {
			return fail("this move doesn't take images")
		}
		bin, err := exec.LookPath("docker")
		if err != nil {
			return fail("docker isn't installed")
		}
		if err := syscall.Exec(bin, []string{"docker", "load"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}); err != nil {
			return fail(err.Error())
		}
		return 0
	}
	rsyncArgs, err := moveReceiveArgs(args[1], m)
	if err != nil {
		return fail(err.Error())
	}
	bin, err := exec.LookPath("rsync")
	if err != nil {
		return fail("rsync isn't installed")
	}
	if err := syscall.Exec(bin, rsyncArgs, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}); err != nil {
		return fail(err.Error())
	}
	return 0
}
