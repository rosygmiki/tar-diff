// Package tarpatch provides functionality for applying binary patches to tar archives.
package tarpatch

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containers/tar-diff/pkg/protocol"
	"github.com/klauspost/compress/zstd"
)

const (
	// maxFilenameSize prevents DoS attacks via excessively long filenames
	maxFilenameSize = 4 * 1024 // 4KB limit for filenames
	// maxAddDataSize prevents DoS attacks via excessive memory allocation for AddData operations
	maxAddDataSize = 100 * 1024 * 1024 // 100MB limit for AddData operations
)

// DataSource provides an interface for reading data during patch application.
type DataSource interface {
	io.ReadSeeker
	io.Closer
	SetCurrentFile(file string) error
}

// FilesystemDataSource implements DataSource by reading from filesystem files.
type FilesystemDataSource struct {
	basePath    string
	currentFile *os.File
}

// NewFilesystemDataSource creates a new FilesystemDataSource with the specified base path.
func NewFilesystemDataSource(basePath string) *FilesystemDataSource {
	return &FilesystemDataSource{
		basePath:    basePath,
		currentFile: nil,
	}
}

// Close closes the current file if one is open.
func (f *FilesystemDataSource) Close() error {
	if f.currentFile != nil {
		err := f.currentFile.Close()
		f.currentFile = nil

		if err != nil {
			return err
		}
	}
	return nil
}

func (f *FilesystemDataSource) Read(data []byte) (n int, err error) {
	if f.currentFile == nil {
		return 0, fmt.Errorf("no current file set")
	}
	return f.currentFile.Read(data)
}

// SetCurrentFile opens the specified file for reading.
func (f *FilesystemDataSource) SetCurrentFile(file string) error {
	if f.currentFile != nil {
		err := f.currentFile.Close()
		f.currentFile = nil
		if err != nil {
			return err
		}
	}
	currentFile, err := os.Open(filepath.Join(f.basePath, file))
	if err != nil {
		return err
	}
	f.currentFile = currentFile
	return nil
}

// Seek changes the read position in the current file.
func (f *FilesystemDataSource) Seek(offset int64, whence int) (int64, error) {
	if f.currentFile == nil {
		return 0, fmt.Errorf("no current file set")
	}
	return f.currentFile.Seek(offset, whence)
}

// validateRequiredFiles scans the delta to collect all required source files and validates they exist.
func validateRequiredFiles(delta io.ReadSeeker, dataSource *FilesystemDataSource) error {
	fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: ENTRY - basePath=%q\n", dataSource.basePath)

	// Read and validate header
	buf := make([]byte, len(protocol.DeltaHeader))
	_, err := io.ReadFull(delta, buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: failed to read header: %v\n", err)
		return err
	}
	if !bytes.Equal(buf, protocol.DeltaHeader[:]) {
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: invalid delta format\n")
		return fmt.Errorf("invalid delta format")
	}

	decoder, err := zstd.NewReader(delta)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: failed to create zstd decoder: %v\n", err)
		return err
	}

	r := bufio.NewReader(decoder)
	requiredFiles := make(map[string]bool)

	// Scan delta to collect all DeltaOpOpen operations
	fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: scanning delta for DeltaOpOpen operations\n")
	opCount := 0
	for {
		op, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: error reading op byte: %v\n", err)
			return err
		}

		size, err := binary.ReadUvarint(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: error reading size: %v\n", err)
			return err
		}

		switch op {
		case protocol.DeltaOpOpen:
			opCount++
			nameBytes := make([]byte, size)
			_, err = io.ReadFull(r, nameBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: error reading filename: %v\n", err)
				return err
			}
			filename := string(nameBytes)
			requiredFiles[filename] = true
			fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: DeltaOpOpen #%d: %q\n", opCount, filename)
		case protocol.DeltaOpData, protocol.DeltaOpAddData:
			// Skip the data bytes
			_, err = io.CopyN(io.Discard, r, int64(size))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: error skipping data: %v\n", err)
				return err
			}
		case protocol.DeltaOpCopy, protocol.DeltaOpSeek:
			// These operations don't have additional data to skip
		}
	}

	// Close decoder before seeking to ensure no buffered data interferes
	decoder.Close()

	fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: scan complete - found %d required files\n", len(requiredFiles))

	// Validate all required files exist
	for file := range requiredFiles {
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: checking file=%q\n", file)

		cleanFile := protocol.CleanPath(file)
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles:   after CleanPath=%q\n", cleanFile)

		if len(cleanFile) == 0 {
			fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles:   SKIPPED (cleanFile is empty)\n")
			continue // Skip invalid paths; Apply() will catch these
		}

		// Convert to native path separators for the current OS
		nativePath := filepath.FromSlash(cleanFile)
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles:   after FromSlash=%q\n", nativePath)

		filePath := filepath.Join(dataSource.basePath, nativePath)
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles:   full path=%q\n", filePath)

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles:   FILE DOES NOT EXIST - returning error\n")
				return fmt.Errorf("required source file does not exist: %s", cleanFile)
			}
			fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles:   os.Stat error: %v\n", err)
			return fmt.Errorf("error accessing source file %s: %w", cleanFile, err)
		}
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles:   EXISTS - size=%d\n", fileInfo.Size())
	}

	fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: all files validated successfully\n")

	// Reset delta reader to the beginning for actual patching
	fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: seeking back to start\n")
	_, err = delta.Seek(0, io.SeekStart)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: seek failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[DEBUG] validateRequiredFiles: EXIT - success\n")
	}
	return err
}

// Apply applies a binary patch from a delta reader to produce output using the data source.
func Apply(delta io.Reader, dataSource DataSource, dst io.Writer) error {
	// Validate required files if we have a seekable delta and FilesystemDataSource
	if seeker, ok := delta.(io.ReadSeeker); ok {
		if fsDataSource, ok := dataSource.(*FilesystemDataSource); ok {
			if err := validateRequiredFiles(seeker, fsDataSource); err != nil {
				return err
			}
		}
	}

	buf := make([]byte, len(protocol.DeltaHeader))
	_, err := io.ReadFull(delta, buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf, protocol.DeltaHeader[:]) {
		return fmt.Errorf("invalid delta format")
	}

	decoder, err := zstd.NewReader(delta)
	if err != nil {
		return err
	}
	defer decoder.Close()

	r := bufio.NewReader(decoder)

	for {
		op, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		size, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}

		switch op {
		case protocol.DeltaOpData:
			_, err = io.CopyN(dst, r, int64(size))
			if err != nil {
				return err
			}
		case protocol.DeltaOpOpen:
			// Validate filename size to prevent DoS attacks
			if size > maxFilenameSize {
				return fmt.Errorf("filename size %d exceeds maximum allowed %d", size, maxFilenameSize)
			}
			nameBytes := make([]byte, size)
			_, err = io.ReadFull(r, nameBytes)
			if err != nil {
				return err
			}
			name := string(nameBytes)
			cleanName := protocol.CleanPath(name)
			if len(cleanName) == 0 {
				return fmt.Errorf("invalid source name '%v' in tar-diff", name)
			}
			err := dataSource.SetCurrentFile(cleanName)
			if err != nil {
				return err
			}
		case protocol.DeltaOpCopy:
			_, err = io.CopyN(dst, dataSource, int64(size))
			if err != nil {
				return err
			}
		case protocol.DeltaOpAddData:
			// Validate AddData size to prevent DoS attacks via excessive memory allocation
			if size > maxAddDataSize {
				return fmt.Errorf("AddData operation size %d exceeds maximum allowed %d", size, maxAddDataSize)
			}
			addBytes := make([]byte, size)
			_, err = io.ReadFull(r, addBytes)
			if err != nil {
				return err
			}

			addBytes2 := make([]byte, size)
			_, err = io.ReadFull(dataSource, addBytes2)
			if err != nil {
				return err
			}

			for i := range size {
				addBytes[i] += addBytes2[i]
			}
			if _, err := dst.Write(addBytes); err != nil {
				return err
			}

		case protocol.DeltaOpSeek:
			_, err = dataSource.Seek(int64(size), io.SeekStart)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected delta op %d", op)
		}
	}

	return nil
}
