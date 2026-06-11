// swift-tools-version: 6.2
import PackageDescription

let package = Package(
	name: "VfsFSKit",
	platforms: [
		.macOS("26.0")
	],
	dependencies: [
		.package(url: "https://github.com/swiftlang/swift-java", from: "0.4.0")
	],
	targets: [
		.executableTarget(
			name: "VfsFSKitExtension",
			dependencies: [
				.product(name: "SwiftJavaStatic", package: "swift-java")
			],
			exclude: ["swift-java.config"],
			swiftSettings: [
				.swiftLanguageMode(.v5)
			],
			linkerSettings: [
				// ExtensionKit extensions must enter through NSExtensionMain (Xcode
				// links appex targets with `-e _NSExtensionMain`). With the default
				// Swift entry point, ExtensionFoundation fails with "Unrecognized
				// extension type" and the extension exits before serving XPC.
				.unsafeFlags(["-Xlinker", "-e", "-Xlinker", "_NSExtensionMain"])
			],
			plugins: [
				.plugin(name: "SwiftJavaPlugin", package: "swift-java")
			]
		),
		.executableTarget(
			name: "VfsFSKitHost"
		)
	]
)
