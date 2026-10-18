import AVFoundation
import SwiftUI
import UIKit

struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    func makeUIViewController(context: Context) -> ScannerController { ScannerController(onCode: onCode) }
    func updateUIViewController(_ controller: ScannerController, context: Context) {}
}

final class ScannerController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "dev.squadtime.prototype.camera")
    private let onCode: (String) -> Void
    private var delivered = false
    private var active = true
    private var preview: AVCaptureVideoPreviewLayer?
    init(onCode: @escaping (String) -> Void) { self.onCode = onCode; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("Unsupported initializer") }
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        Task { @MainActor in
            let allowed = await AVCaptureDevice.requestAccess(for: .video)
            guard active else { return }
            guard allowed, let camera = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: camera), session.canAddInput(input) else {
                let label = UILabel(); label.text = "Camera unavailable. Use manual paste instead."
                label.textColor = .white; label.numberOfLines = 0; label.textAlignment = .center
                label.frame = view.bounds; label.autoresizingMask = [.flexibleWidth, .flexibleHeight]; view.addSubview(label)
                return
            }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output); output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: session); layer.videoGravity = .resizeAspectFill
            view.layer.insertSublayer(layer, at: 0); preview = layer; layer.frame = view.bounds
            let capture = SessionRunner(session: session)
            queue.async { capture.start() }
        }
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        active = false
        let capture = SessionRunner(session: session)
        queue.async { capture.stop() }
    }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !delivered, let code = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        delivered = true; onCode(code)
    }
}

// AVCaptureSession is confined to this serial camera queue after initial configuration.
private final class SessionRunner: @unchecked Sendable {
    let session: AVCaptureSession
    init(session: AVCaptureSession) { self.session = session }
    func start() { session.startRunning() }
    func stop() { session.stopRunning() }
}
