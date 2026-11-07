package steps

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

// caddyPackageMax caps a package unpacked: a Caddy setup is a few small files.
const caddyPackageMax = 32 << 20

// caddyPackageSites is the folder of site files. Those already on the server, and
// its .env, stay when a package comes again: they belong to the server.
const caddyPackageSites = "core/prod/caddy/configs/"

type caddyPackageFile struct {
	name string
	mode os.FileMode
	body []byte
}

// readCaddyPackage opens a package: base64 of a .tar.gz, nothing but plain files
// and folders inside it, none of them climbing out, with the compose file a setup
// has to have. It comes from a program, and what it unpacks runs in Docker.
func readCaddyPackage(data string) ([]caddyPackageFile, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.New("the Caddy package isn't base64")
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("the Caddy package isn't a .tar.gz")
	}
	defer gz.Close()

	var files []caddyPackageFile
	var total int64
	hasCompose := false
	archive := tar.NewReader(gz)
	for {
		h, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the Caddy package can't be read: %w", err)
		}
		name := path.Clean(h.Name)
		if name == "." {
			continue
		}
		if path.IsAbs(h.Name) || name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("the Caddy package names a path outside itself: %s", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("the Caddy package holds something other than files and folders: %s", h.Name)
		}
		if total += h.Size; total > caddyPackageMax {
			return nil, errors.New("the Caddy package is too big")
		}
		body, err := io.ReadAll(io.LimitReader(archive, caddyPackageMax+1))
		if err != nil {
			return nil, fmt.Errorf("the Caddy package can't be read: %w", err)
		}
		mode := os.FileMode(0o644)
		if h.Mode&0o111 != 0 {
			mode = 0o755
		}
		files = append(files, caddyPackageFile{name: name, mode: mode, body: body})
		hasCompose = hasCompose || name == "docker-compose.prod.yml"
	}
	if !hasCompose {
		return nil, errors.New("the Caddy package has no docker-compose.prod.yml at its top: is it a Caddy setup?")
	}
	return files, nil
}

// installCaddyPackage puts a package at dir for user. With none (running again
// from what's kept) what's there stays, and the stack is brought up as it is.
func installCaddyPackage(user, dir, data string) error {
	if data == "" {
		if !system.DryRun && !system.FileExists(dir+"/docker-compose.prod.yml") {
			return errors.New("no Caddy package was sent, and none is unpacked in " + dir)
		}
		return nil
	}
	files, err := readCaddyPackage(data)
	if err != nil {
		return err
	}
	sites := dir + "/" + caddyPackageSites
	if _, err := system.Run("install", "-d", "-o", user, "-g", user, dir, sites); err != nil {
		return err
	}
	for _, f := range files {
		p := dir + "/" + f.name
		kept := f.name == ".env" || strings.HasPrefix(f.name, caddyPackageSites)
		if kept && system.FileExists(p) {
			continue
		}
		if _, err := system.Run("install", "-d", "-o", user, "-g", user, path.Dir(p)); err != nil {
			return err
		}
		if err := system.WriteFile(p, string(f.body), f.mode); err != nil {
			return err
		}
	}
	_, err = system.Run("chown", "-R", user+":"+user, dir)
	return err
}
