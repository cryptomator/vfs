import FSKit

/// Per-item state; all mutation is confined to the `VfsItemTable` actor.
/// FSKit keeps removed items alive until `reclaimItem`, so an unlinked item
/// retains its Java handle for in-flight I/O.
final class VfsItem: FSItem, @unchecked Sendable {

	let id: FSItem.Identifier
	var parentID: FSItem.Identifier
	var path: String
	var type: FSItem.ItemType
	var javaHandle: Int64 = 0
	var grantedModes: FSVolume.OpenModes = []
	var unlinked = false
	var lastKnownAttributes: NodeAttributes?

	init(id: FSItem.Identifier, parentID: FSItem.Identifier, path: String, type: FSItem.ItemType) {
		self.id = id
		self.parentID = parentID
		self.path = path
		self.type = type
		super.init()
	}
}
