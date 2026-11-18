import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = NSRect(x: 180, y: 140, width: 1120, height: 760)
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.minSize = NSSize(width: 860, height: 600)
    self.title = "PhishLens — macOS Link Inspector"
    self.appearance = NSAppearance(named: .darkAqua)
    self.backgroundColor = NSColor(calibratedRed: 0.094, green: 0.094, blue: 0.094, alpha: 1.0)

    RegisterGeneratedPlugins(registry: flutterViewController)

    if let appDelegate = NSApp.delegate as? AppDelegate {
      appDelegate.attachFlutterEngine(controller: flutterViewController, window: self)
    }

    super.awakeFromNib()
  }
}
