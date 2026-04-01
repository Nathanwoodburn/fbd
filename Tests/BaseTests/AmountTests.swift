import XCTest
@testable import Base

final class AmountTests: XCTestCase {

    // MARK: - Construction

    func testZero() {
        XCTAssertEqual(Amount.zero.bumps, 0)
    }

    func testFromDollarydoos() throws {
        let amount = try Amount(1_000_000)
        XCTAssertEqual(amount.bumps, 1_000_000)
    }

    func testFromCoins() throws {
        let amount = try Amount.coins(5)
        XCTAssertEqual(amount.bumps, 5_000_000)
    }

    func testFBCConversion() throws {
        let amount = try Amount(2_500_000)
        XCTAssertEqual(amount.fbc, 2.5, accuracy: 0.0001)
    }

    // MARK: - Validation

    func testNegativeAmountThrows() {
        XCTAssertThrowsError(try Amount(-1))
    }

    func testOverMaxMoneyThrows() {
        XCTAssertThrowsError(try Amount(Amount.maxMoney + 1))
    }

    func testMaxMoneySucceeds() throws {
        let amount = try Amount(Amount.maxMoney)
        XCTAssertEqual(amount.bumps, Amount.maxMoney)
    }

    // MARK: - Arithmetic

    func testAddition() throws {
        let a = try Amount(1_000_000)
        let b = try Amount(2_000_000)
        let sum = a + b
        XCTAssertEqual(sum.bumps, 3_000_000)
    }

    func testSubtraction() throws {
        let a = try Amount(5_000_000)
        let b = try Amount(2_000_000)
        let diff = a - b
        XCTAssertEqual(diff.bumps, 3_000_000)
    }

    func testSubtractionCanBeNegative() throws {
        let a = try Amount(1_000_000)
        let b = try Amount(2_000_000)
        let diff = a - b
        XCTAssertEqual(diff.bumps, -1_000_000)
    }

    // MARK: - Comparable

    func testComparable() throws {
        let a = try Amount(100)
        let b = try Amount(200)
        XCTAssertTrue(a < b)
        XCTAssertFalse(b < a)
        XCTAssertFalse(a < a)
    }

    // MARK: - Equatable

    func testEquatable() throws {
        let a = try Amount(42)
        let b = try Amount(42)
        let c = try Amount(43)
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }
}
