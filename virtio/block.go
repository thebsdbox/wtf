package virtio

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/vm-tools/wtf/virtio/virtq"
)

// BlockDevice configures a virtio block device.
type BlockDevice struct {

	// ReadOnly forces the device to be read-only.
	ReadOnly bool

	// Storage is the backing storage for the device. Storage may also
	// implement the io.WriterAt interface to enable writes.
	Storage BlockStorage
}

// BlockStorage is the basic interface to a block device's backing storage. It is
// read-only: To enable writes, storage types should also implement io.WriterAt.
type BlockStorage interface {
	io.ReaderAt

	// Size returns the storage size in bytes.
	Size() (int64, error)
}

// MemStorage is read-write block storage backed by a byte slice.
type MemStorage struct {
	Bytes []byte
}

// FileStorage is read-write block storage backed by a file.
type FileStorage struct {
	File *os.File
}

// HTTP storage is read-only block storage backed by an HTTP URL.
// The server must support HEAD requests and GET requests with a Range header.
type HTTPStorage struct {
	URL string

	// Client is the HTTP client to use for requests.
	// If nil, http.DefaultClient is used.
	Client *http.Client
}

type blockHandler struct {
	cfg BlockDevice
	r   io.ReaderAt
	w   io.WriterAt
	wg  sync.WaitGroup
}

// blkConfig has the same fields as struct virtio_blk_config.
type blkConfig struct {
	// 	le64 capacity;
	Capacity uint64 // expressed in 512-byte sectors
	// 	le32 size_max;
	SizeMax uint32
	// 	le32 seg_max;
	SegMax uint32
	// 	struct virtio_blk_geometry {
	// 			le16 cylinders;
	// 			u8 heads;
	// 			u8 sectors;
	// 	} geometry;
	Geometry struct {
		Cylinders uint16
		Heads     uint8
		Sectors   uint8
	}
	// 	le32 blk_size;
	BlkSize uint32
	// 	struct virtio_blk_topology {
	// 			// # of logical blocks per physical block (log2)
	// 			u8 physical_block_exp;
	// 			// offset of first aligned logical block
	// 			u8 alignment_offset;
	// 			// suggested minimum I/O size in blocks
	// 			le16 min_io_size;
	// 			// optimal (suggested maximum) I/O size in blocks
	// 			le32 opt_io_size;
	// 	} topology;
	Topology struct {
		PhysicalBlockExp uint8
		AlignmentOffset  uint8
		MinIOSize        uint16
		OptIOSize        uint32
	}
	// 	u8 writeback;
	Writeback uint8
	// u8 unused0;
	_ byte
	// u16 num_queues;
	NumQueues uint16
	// 	le32 max_discard_sectors;
	MaxDiscardSectors uint32
	// 	le32 max_discard_seg;
	MaxDiscardSeg uint32
	// 	le32 discard_sector_alignment;
	DiscardSectorAlignment uint32
	// 	le32 max_write_zeroes_sectors;
	MaxWriteZeroesSectors uint32
	// 	le32 max_write_zeroes_seg;
	MaxWriteZeroesSeg uint32
	// 	u8 write_zeroes_may_unmap;
	WriteZeroesMayUnmap uint8
	// 	u8 unused1[3];
	_ [3]byte
	// le32 max_secure_erase_sectors;
	MaxSecureEraseSectors uint32
	// le32 max_secure_erase_seg;
	MaxSecureEraseSeg uint32
	// le32 secure_erase_sector_alignment;
	SecureEraseSectorAlignment uint32
	// };
}

// features

const (
	blkFSizeMax     = 1 << 0  // max size of any single segment is in size_max
	blkFSegMac      = 1 << 1  // max number of segments in a request is in seg_max
	blkFGeometry    = 1 << 3  // disk-style geometry specified in geometry
	blkFRO          = 1 << 4  // device is read-only
	blkFBlkSize     = 1 << 5  // block size of disk is in blk_size
	blkFFlush       = 1 << 8  // cache flush command support
	blkFTopology    = 1 << 9  // device exports information on optimal I/O alignment
	blkFConfigWCE   = 1 << 10 // device can toggle its cache between writeback and writethrough modes
	blkFMQ          = 1 << 11 // device supports multiqueue
	blkFDiscard     = 1 << 12 // max discard sectors size in max_discard_sectors and max discard segment number in max_discard_seg
	blkFWriteZeroes = 1 << 13 // max write zeroes sectors size in max_write_zeroes_sectors and max write zeroes segment number in max_write_zeroes_seg
	blkFLifetime    = 1 << 14 // device supports providing storage lifetime information
	blkFSecureErase = 1 << 15 // device supports secure erase command, maximum erase sectors count in max_secure_erase_sectors and maximum erase segment number in max_secure_erase_seg
)

// op type

const (
	blkTIn          = 0
	blkTOut         = 1
	blkTFlush       = 4
	blkTGetID       = 8
	blkTGetLifetime = 10
	blkTDiscard     = 11
	blkTWriteZeroes = 13
	blkTSecureErase = 14
)

// op status

const (
	blkSOK     = 0
	blkSIOErr  = 1
	blkSUnsupp = 2
)

func (cfg BlockDevice) NewHandler() (DeviceHandler, error) {
	h := &blockHandler{cfg: cfg, r: cfg.Storage}

	if !cfg.ReadOnly {
		h.w, _ = cfg.Storage.(io.WriterAt)
	}

	return h, nil
}

func (h *blockHandler) GetType() DeviceID {
	return BlockDeviceID
}

func (h *blockHandler) GetFeatures() (features uint64) {
	if h.w == nil {
		return blkFRO
	}

	return
}

func (h *blockHandler) Ready(negotiatedFeatures uint64) error {
	if h.w == nil && negotiatedFeatures&blkFRO == 0 {
		panic("block device is read-only")
	}

	return nil
}

func (h *blockHandler) QueueReady(num int, q *virtq.Queue, notify <-chan struct{}) error {
	if num == 0 {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			for range notify {
				if err := h.handle(q); err != nil {
					slog.Error("block handler", "error", err)
				}
			}
		}()
	}

	return nil
}

func (h *blockHandler) handle(q *virtq.Queue) error {
	for {
		c, err := q.Next()
		if err != nil {
			return err
		}

		if c == nil {
			return nil
		}

		if len(c.Desc) != 3 {
			panic("invalid descriptor chain length")
		}

		hd := c.Desc[0]
		dd := c.Desc[1]
		sd := c.Desc[2]

		if !hd.IsRO() {
			panic("descriptor 0 (hdr) is not read-only")
		}

		if !sd.IsWO() {
			panic("descriptor 2 (status) is not write-only")
		}

		hdr, err := c.Buf(0)
		if err != nil {
			return err
		}

		if len(hdr) != 16 {
			panic("invalid hdr buffer length")
		}

		data, err := c.Buf(1)
		if err != nil {
			return err
		}

		status, err := c.Buf(2)
		if err != nil {
			return err
		}

		if len(status) != 1 {
			panic("invalid status buffer length")
		}

		var (
			optype = binary.LittleEndian.Uint32(hdr)
			offsec = binary.LittleEndian.Uint32(hdr[8:])
		)

		var n int
		switch optype {
		case blkTIn:
			if !dd.IsWO() {
				panic("descriptor 1 (data) is not write-only")
			}

			n, err = h.cfg.Storage.ReadAt(data, int64(offsec)*512)

		case blkTOut:
			if h.w == nil {
				status[0] = blkSUnsupp
				break
			}

			if !dd.IsRO() {
				panic("descriptor 1 (data) is not read-only")
			}

			n, err = h.w.WriteAt(data, int64(offsec)*512)

		default:
			status[0] = blkSUnsupp
		}

		if err != nil {
			status[0] = blkSIOErr
			slog.Error("block io error", "err", err)
		}

		// FIX: +1 for the status byte?
		if err := c.Release(n); err != nil {
			return err
		}
	}
}

func (h *blockHandler) ReadConfig(p []byte, off int) error {
	cfg, err := h.getBlkConfig()
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, cfg); err != nil {
		return err
	}

	raw := buf.Bytes()
	copy(p, raw[off:])

	return nil
}

func (h *blockHandler) Close() error {
	h.wg.Wait()
	return nil
}

func (h *blockHandler) getBlkConfig() (*blkConfig, error) {
	sz, err := h.cfg.Storage.Size()
	if err != nil {
		return nil, err
	}

	if sz%512 != 0 {
		panic("sz % 512 != 0")
	}

	cfg := blkConfig{
		Capacity: uint64(sz / 512),
	}

	return &cfg, nil
}

// ReadAt copies from the backing slice at off into p.
func (ms *MemStorage) ReadAt(p []byte, off int64) (n int, err error) {
	return copy(p, ms.Bytes[off:]), nil
}

// Size returns the size of the backing slice in bytes.
func (ms *MemStorage) Size() (int64, error) {
	return int64(len(ms.Bytes)), nil
}

// WriteAt copies p into the backing slice at off.
func (ms *MemStorage) WriteAt(p []byte, off int64) (n int, err error) {
	return copy(ms.Bytes[off:], p), nil
}

// ReadAt reads from the backing file.
func (fs *FileStorage) ReadAt(p []byte, off int64) (n int, err error) {
	return fs.File.ReadAt(p, off)
}

// Size stats the backing file and returns its size in bytes.
func (fs *FileStorage) Size() (int64, error) {
	info, err := fs.File.Stat()
	if err != nil {
		return 0, err
	}

	return info.Size(), nil
}

// WriteAt writes to the backing file.
func (fs *FileStorage) WriteAt(p []byte, off int64) (n int, err error) {
	return fs.File.WriteAt(p, off)
}

// ReadAt gets the backing URL with a Range header generated from off and len(p).
func (hs *HTTPStorage) ReadAt(p []byte, off int64) (n int, err error) {
	req, err := http.NewRequest(http.MethodGet, hs.URL, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("range", fmt.Sprintf("bytes=%d-%d", off, off+int64(len(p))-1))

	res, err := hs.getClient().Do(req)
	if err != nil {
		return
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("block device http request failed: GET %s: status %d != %d",
			hs.URL, res.StatusCode, http.StatusPartialContent)
	}

	n, err = res.Body.Read(p)
	if err == io.EOF && n == len(p) {
		err = nil
	}

	return
}

// Size sends a HEAD request to the backing URL and parses the Content-Length response header.
func (hs *HTTPStorage) Size() (int64, error) {
	res, err := hs.getClient().Head(hs.URL)
	if err != nil {
		return 0, err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNotModified {
		return 0, fmt.Errorf("block device http request failed: HEAD %s: status %d", hs.URL, res.StatusCode)
	}

	cl := res.Header.Get("content-length")
	return strconv.ParseInt(cl, 10, 64)
}

func (hs *HTTPStorage) getClient() *http.Client {
	if hs.Client != nil {
		return hs.Client
	}

	return http.DefaultClient
}
