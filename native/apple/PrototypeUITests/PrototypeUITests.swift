import XCTest

@MainActor
final class PrototypeUITests: XCTestCase {
    func testLocalOnboardingSurvivesProcessRestart() throws {
        let app = XCUIApplication()
        app.launch()
        let nickname = app.textFields["Synthetic nickname"]
        if nickname.waitForExistence(timeout: 5) {
            nickname.tap(); nickname.typeText("Synthetic iOS")
            app.buttons["Create local profile"].tap()
        }
        XCTAssertTrue(app.staticTexts["Synthetic iOS"].waitForExistence(timeout: 5))
        app.terminate(); app.launch()
        XCTAssertTrue(app.staticTexts["Synthetic iOS"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.textFields["Synthetic nickname"].exists)
        XCTAssertTrue(app.buttons["Approve test relay origin"].exists)
    }
}
