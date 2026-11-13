"""VPC Flow Log parser with incremental parsing support."""

import io
import json
import gzip
from typing import List, Iterator, Union, BinaryIO
from pathlib import Path
from dataclasses import dataclass

from shared.netwatch_core.schemas.flow_log import FlowLogEntry


@dataclass
class ParseResult:
    """Result of parsing a flow log file."""
    entries: List[FlowLogEntry]
    total_lines: int
    parsed_lines: int
    failed_lines: int
    errors: List[str]


class IncrementalGZIPReader:
    """Incremental GZIP decompressor that yields lines without full decompression."""
    
    def __init__(self, file_obj: BinaryIO, chunk_size: int = 8192):
        self.gz = gzip.GzipFile(fileobj=file_obj, mode='rb')
        self.buffer = b''
        self.chunk_size = chunk_size
        self.closed = False
    
    def __iter__(self):
        return self
    
    def __next__(self) -> bytes:
        while True:
            # Try to find a complete line in buffer
            if b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                return line
            
            # Read more data
            try:
                chunk = self.gz.read(self.chunk_size)
            except (EOFError, OSError):
                # Handle truncated/corrupt GZIP gracefully
                chunk = b''
            
            if not chunk:
                # EOF - return remaining buffer if any
                if self.buffer:
                    line = self.buffer
                    self.buffer = b''
                    return line
                raise StopIteration
            
            self.buffer += chunk
    
    def close(self):
        if not self.closed:
            self.gz.close()
            self.closed = True


class FlowLogParser:
    """Parser for AWS VPC Flow Logs with incremental parsing support."""

    def __init__(self):
        self.errors: List[str] = []

    def parse_file(self, file_path: Union[str, Path]) -> ParseResult:
        """Parse a flow log file (JSON, JSONL, or gzipped) incrementally."""
        path = Path(file_path)
        self.errors = []

        if path.suffix == '.gz':
            return self._parse_gzipped(path)
        elif path.suffix == '.json':
            return self._parse_json(path)
        else:
            return self._parse_jsonl(path)

    def parse_bytes(self, content: bytes, filename: str) -> ParseResult:
        """Parse flow logs from raw bytes (handles .json, .jsonl, .gz)."""
        self.errors = []
        
        # Detect format by magic bytes (gzip) or filename
        if filename.endswith('.gz') or (len(content) >= 2 and content[:2] == b'\x1f\x8b'):
            return self._parse_gzipped_bytes(content)
        elif filename.endswith('.json'):
            return self._parse_json_bytes(content)
        else:
            # Treat as JSONL
            return self._parse_jsonl_bytes(content)

    def parse_stream(self, file_obj: BinaryIO, filename: str) -> ParseResult:
        """Parse flow logs from a file-like object incrementally."""
        self.errors = []
        
        if filename.endswith('.gz'):
            return self._parse_gzipped_stream(file_obj)
        elif filename.endswith('.json'):
            return self._parse_json_stream(file_obj)
        else:
            return self._parse_jsonl_stream(file_obj)

    def _parse_gzipped(self, path: Path) -> ParseResult:
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0

        with gzip.open(path, 'rt', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = self._parse_line(line)
                    entries.append(entry)
                    parsed_lines += 1
                except Exception as e:
                    failed_lines += 1
                    self.errors.append(f"Line {line_num}: {str(e)}")

        return ParseResult(entries, total_lines, parsed_lines, failed_lines, self.errors)

    def _parse_gzipped_bytes(self, content: bytes) -> ParseResult:
        """Parse GZIP bytes incrementally without full decompression."""
        self.errors = []
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0
        
        try:
            # Use incremental decompression
            reader = IncrementalGZIPReader(io.BytesIO(content))
            for line_num, line_bytes in enumerate(reader, 1):
                total_lines += 1
                try:
                    line = line_bytes.decode('utf-8').strip()
                except UnicodeDecodeError as e:
                    failed_lines += 1
                    self.errors.append(f"Line {line_num}: UTF-8 decode failed: {str(e)}")
                    continue
                
                if not line:
                    continue
                
                try:
                    entry = self._parse_line(line)
                    entries.append(entry)
                    parsed_lines += 1
                except Exception as e:
                    failed_lines += 1
                    self.errors.append(f"Line {line_num}: {str(e)}")
            reader.close()
        except (gzip.BadGzipFile, OSError, UnicodeDecodeError) as e:
            self.errors.append(f"GZIP decompression failed: {str(e)}")
            return ParseResult([], 0, 0, 1, self.errors)

        return ParseResult(entries, total_lines, parsed_lines, failed_lines, self.errors)

    def _parse_gzipped_stream(self, file_obj: BinaryIO) -> ParseResult:
        """Parse GZIP stream incrementally."""
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0
        self.errors = []

        try:
            reader = IncrementalGZIPReader(file_obj)
            for line_num, line_bytes in enumerate(reader, 1):
                total_lines += 1
                try:
                    line = line_bytes.decode('utf-8').strip()
                except UnicodeDecodeError as e:
                    failed_lines += 1
                    self.errors.append(f"Line {line_num}: UTF-8 decode failed: {str(e)}")
                    continue
                
                if not line:
                    continue
                
                try:
                    entry = self._parse_line(line)
                    entries.append(entry)
                    parsed_lines += 1
                except Exception as e:
                    failed_lines += 1
                    self.errors.append(f"Line {line_num}: {str(e)}")
            reader.close()
        except (gzip.BadGzipFile, OSError, UnicodeDecodeError) as e:
            self.errors.append(f"GZIP decompression failed: {str(e)}")
            return ParseResult([], 0, 0, 1, self.errors)

        return ParseResult(entries, total_lines, parsed_lines, failed_lines, self.errors)

    def _parse_json(self, path: Path) -> ParseResult:
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0

        with open(path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            return self._parse_json_text(content)

    def _parse_json_bytes(self, content: bytes) -> ParseResult:
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError as e:
            self.errors.append(f"UTF-8 decode failed: {str(e)}")
            return ParseResult([], 0, 0, 1, self.errors)
        return self._parse_json_text(text)

    def _parse_json_stream(self, file_obj: BinaryIO) -> ParseResult:
        try:
            content = file_obj.read().decode('utf-8')
        except UnicodeDecodeError as e:
            self.errors.append(f"UTF-8 decode failed: {str(e)}")
            return ParseResult([], 0, 0, 1, self.errors)
        return self._parse_json_text(content)

    def _parse_json_text(self, text: str) -> ParseResult:
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0
        self.errors = []

        try:
            data = json.loads(text.strip())
            if isinstance(data, list):
                for line_num, item in enumerate(data, 1):
                    total_lines += 1
                    try:
                        entry = self._parse_dict(item)
                        entries.append(entry)
                        parsed_lines += 1
                    except Exception as e:
                        failed_lines += 1
                        self.errors.append(f"Item {line_num}: {str(e)}")
            else:
                total_lines = 1
                try:
                    entry = self._parse_dict(data)
                    entries.append(entry)
                    parsed_lines = 1
                except Exception as e:
                    failed_lines = 1
                    self.errors.append(f"Item 1: {str(e)}")
        except json.JSONDecodeError as e:
            total_lines = 1
            failed_lines = 1
            self.errors.append(f"Invalid JSON: {str(e)}")

        return ParseResult(entries, total_lines, parsed_lines, failed_lines, self.errors)

    def _parse_jsonl(self, path: Path) -> ParseResult:
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0

        with open(path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = self._parse_dict(data)
                    entries.append(entry)
                    parsed_lines += 1
                except Exception as e:
                    failed_lines += 1
                    self.errors.append(f"Line {line_num}: {str(e)}")

        return ParseResult(entries, total_lines, parsed_lines, failed_lines, self.errors)

    def _parse_jsonl_bytes(self, content: bytes) -> ParseResult:
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError as e:
            self.errors.append(f"UTF-8 decode failed: {str(e)}")
            return ParseResult([], 0, 0, 1, self.errors)
        return self._parse_jsonl_text(text)

    def _parse_jsonl_stream(self, file_obj: BinaryIO) -> ParseResult:
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0
        self.errors = []

        for line_num, line in enumerate(file_obj, 1):
            total_lines += 1
            try:
                text_line = line.decode('utf-8').strip()
            except UnicodeDecodeError as e:
                failed_lines += 1
                self.errors.append(f"Line {line_num}: UTF-8 decode failed: {str(e)}")
                continue
            
            if not text_line:
                continue
            try:
                data = json.loads(text_line)
                entry = self._parse_dict(data)
                entries.append(entry)
                parsed_lines += 1
            except Exception as e:
                failed_lines += 1
                self.errors.append(f"Line {line_num}: {str(e)}")

        return ParseResult(entries, total_lines, parsed_lines, failed_lines, self.errors)

    def _parse_jsonl_text(self, text: str) -> ParseResult:
        entries = []
        total_lines = 0
        parsed_lines = 0
        failed_lines = 0
        self.errors = []

        for line_num, line in enumerate(text.splitlines(), 1):
            total_lines += 1
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entry = self._parse_dict(data)
                entries.append(entry)
                parsed_lines += 1
            except Exception as e:
                failed_lines += 1
                self.errors.append(f"Line {line_num}: {str(e)}")

        return ParseResult(entries, total_lines, parsed_lines, failed_lines, self.errors)

    def _parse_line(self, line: str) -> FlowLogEntry:
        """Parse a single JSON line."""
        data = json.loads(line)
        return self._parse_dict(data)

    def _parse_dict(self, data: dict) -> FlowLogEntry:
        """Parse a dictionary into FlowLogEntry."""
        required_fields = [
            'version', 'account_id', 'interface_id', 'src_addr', 'dst_addr',
            'src_port', 'dst_port', 'protocol', 'packets', 'bytes',
            'start_time', 'end_time', 'action', 'log_status'
        ]

        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")

        return FlowLogEntry(
            version=data['version'],
            account_id=data['account_id'],
            interface_id=data['interface_id'],
            src_addr=data['src_addr'],
            dst_addr=data['dst_addr'],
            src_port=int(data['src_port']),
            dst_port=int(data['dst_port']),
            protocol=int(data['protocol']),
            packets=int(data['packets']),
            bytes=int(data['bytes']),
            start_time=int(data['start_time']),
            end_time=int(data['end_time']),
            action=data['action'],
            log_status=data['log_status']
        )

    def parse_stream(self, lines: Iterator[str]) -> Iterator[FlowLogEntry]:
        """Parse flow logs from a stream of lines."""
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                yield self._parse_line(line)
            except Exception:
                continue


def parse_flow_log_file(file_path: Union[str, Path]) -> ParseResult:
    """Convenience function to parse a flow log file."""
    parser = FlowLogParser()
    return parser.parse_file(file_path)