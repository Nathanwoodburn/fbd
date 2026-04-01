/// Simple byte accumulation buffer replacing NIO's ByteBuffer.
///
/// Used for frame reassembly in Brontide and packet decoding.
public struct AccumulationBuffer: Sendable {
    private var storage: [UInt8] = []
    private var readIndex: Int = 0

    public init() {}

    /// Number of bytes available to read.
    public var readableBytes: Int {
        storage.count - readIndex
    }

    /// Append bytes to the buffer.
    public mutating func append(_ bytes: [UInt8]) {
        storage.append(contentsOf: bytes)
    }

    /// Peek at `count` bytes without consuming them.
    /// Returns nil if not enough bytes are available.
    public func peek(_ count: Int) -> [UInt8]? {
        guard readableBytes >= count else { return nil }
        return Array(storage[readIndex..<(readIndex + count)])
    }

    /// Consume and return `count` bytes.
    /// Returns nil if not enough bytes are available.
    public mutating func consume(_ count: Int) -> [UInt8]? {
        guard readableBytes >= count else { return nil }
        let data = Array(storage[readIndex..<(readIndex + count)])
        readIndex += count
        return data
    }

    /// Discard consumed bytes and compact the storage.
    /// Call periodically to prevent unbounded growth.
    public mutating func compact() {
        guard readIndex > 0 else { return }
        storage.removeFirst(readIndex)
        readIndex = 0
    }

    /// Remove all data.
    public mutating func clear() {
        storage.removeAll()
        readIndex = 0
    }
}
