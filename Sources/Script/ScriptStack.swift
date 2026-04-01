/// The execution stack for script interpretation.
///
/// Each item on the stack is a byte array. Numbers are encoded/decoded
/// using ``ScriptNum`` when needed by arithmetic or comparison operations.
public struct ScriptStack: Sendable {
    /// Maximum combined stack size (main + alt).
    public static let maxSize = 1000

    /// The stack items (top is at the end).
    public private(set) var items: [[UInt8]]

    /// Create an empty stack.
    public init() {
        self.items = []
    }

    /// Create a stack initialized with the given items.
    public init(_ items: [[UInt8]]) {
        self.items = items
    }

    /// The number of items on the stack.
    public var count: Int { items.count }

    /// Whether the stack is empty.
    public var isEmpty: Bool { items.isEmpty }

    // MARK: - Push / Pop

    /// Push a byte array onto the stack.
    public mutating func push(_ data: [UInt8]) {
        items.append(data)
    }

    /// Push a boolean value onto the stack.
    public mutating func pushBool(_ value: Bool) {
        push(value ? [0x01] : [])
    }

    /// Push a script number onto the stack.
    public mutating func pushInt(_ value: Int64) {
        push(ScriptNum.encode(value))
    }

    /// Pop the top item from the stack.
    public mutating func pop() throws -> [UInt8] {
        guard let item = items.popLast() else {
            throw ScriptError.stackUnderflow
        }
        return item
    }

    /// Pop the top item and decode it as a script number.
    public mutating func popInt(maxSize: Int = ScriptNum.defaultMaxSize) throws -> Int64 {
        let data = try pop()
        return try ScriptNum.decode(data, maxSize: maxSize)
    }

    /// Pop the top item and interpret it as a boolean.
    public mutating func popBool() throws -> Bool {
        let data = try pop()
        return ScriptNum.castToBool(data)
    }

    // MARK: - Peek

    /// Peek at the item at `depth` from the top (0 = top).
    public func peek(_ depth: Int = 0) throws -> [UInt8] {
        let index = items.count - 1 - depth
        guard index >= 0 else {
            throw ScriptError.stackUnderflow
        }
        return items[index]
    }

    /// Peek at the top item and decode as a script number.
    public func peekInt(_ depth: Int = 0, maxSize: Int = ScriptNum.defaultMaxSize) throws -> Int64 {
        let data = try peek(depth)
        return try ScriptNum.decode(data, maxSize: maxSize)
    }

    // MARK: - Manipulation

    /// Remove the item at `depth` from the top (0 = top).
    @discardableResult
    public mutating func remove(at depth: Int) throws -> [UInt8] {
        let index = items.count - 1 - depth
        guard index >= 0 else {
            throw ScriptError.stackUnderflow
        }
        return items.remove(at: index)
    }

    /// Insert an item at `depth` from the top.
    public mutating func insert(_ data: [UInt8], at depth: Int) {
        let index = items.count - depth
        items.insert(data, at: index)
    }

    /// Swap the top two items.
    public mutating func swap() throws {
        guard items.count >= 2 else {
            throw ScriptError.stackUnderflow
        }
        items.swapAt(items.count - 1, items.count - 2)
    }

    /// Duplicate the top item.
    public mutating func dup() throws {
        guard !items.isEmpty else {
            throw ScriptError.stackUnderflow
        }
        items.append(items[items.count - 1])
    }
}
