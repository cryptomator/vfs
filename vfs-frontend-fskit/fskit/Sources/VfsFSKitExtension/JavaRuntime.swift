import Foundation
import SwiftJava

/// Boots and holds the embedded JVM. `scripts/package.sh` bundles a jlink
/// runtime image at `Resources/runtime` and the Java classpath jars at
/// `Resources/libs`.
final class JavaRuntime: @unchecked Sendable {

	private static let lock = NSLock()
	private nonisolated(unsafe) static var instance: JavaRuntime?

	let vm: JavaVirtualMachine

	static func shared() throws -> JavaRuntime {
		lock.lock()
		defer { lock.unlock() }
		if let instance {
			return instance
		}
		let created = try JavaRuntime()
		instance = created
		return created
	}

	private init() throws {
		let resources = Bundle.main.resourceURL!
		let runtime = resources.appendingPathComponent("runtime", isDirectory: true)
		if FileManager.default.fileExists(atPath: runtime.path) {
			setenv("JAVA_HOME", runtime.path, 1)
		}
		let libs = resources.appendingPathComponent("libs", isDirectory: true)
		let jars = ((try? FileManager.default.contentsOfDirectory(atPath: libs.path)) ?? [])
			.filter { $0.hasSuffix(".jar") }
			.sorted()
			.map { libs.appendingPathComponent($0).path }
		var vmOptions: [String] = []
		if ProcessInfo.processInfo.environment["VFS_FSKIT_DEBUG"] == nil {
			// the bundled vfs-test simplelogger.properties enables debug logging, which would leak file paths
			vmOptions.append("-Dorg.slf4j.simpleLogger.defaultLogLevel=info")
		}
		self.vm = try JavaVirtualMachine.shared(classpath: jars, vmOptions: vmOptions)
	}
}
