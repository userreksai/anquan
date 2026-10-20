package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type journal struct {
	JobID           string `json:"job_id"`
	Version         string `json:"version"`
	PreviousVersion string `json:"previous_version"`
	BinarySHA256    string `json:"binary_sha256"`
	PreviousSHA256  string `json:"previous_sha256"`
	Status          string `json:"status"`
	Error           string `json:"error,omitempty"`
}

func hashFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxBinarySize {
		return "", errors.New("update file is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, MaxBinarySize+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readJournal(directory string) (journal, error) {
	var state journal
	path := filepath.Join(directory, "journal.json")
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<10 || !privatePermissions(info.Mode()) {
		return state, errors.New("unsafe update journal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if json.Unmarshal(data, &state) != nil || !jobPattern.MatchString(state.JobID) || !validHash(state.BinarySHA256) || !validHash(state.PreviousSHA256) {
		return state, errors.New("invalid update journal")
	}
	return state, nil
}

func writeJournal(directory string, state journal) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicFile(filepath.Join(directory, "journal.json"), data, 0600)
}

func atomicFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func copyExecutable(source, destination string) error {
	if _, err := hashFile(source); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(destination), ".binary-*")
	if err != nil {
		return err
	}
	temp := output.Name()
	defer os.Remove(temp)
	if err = output.Chmod(0700); err == nil {
		_, err = io.Copy(output, input)
	}
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp, destination); err != nil {
		return fmt.Errorf("replace update executable: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return syncDirectoryFile(file)
}
