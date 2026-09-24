// zoptia0boringssl — root build entry point.
//
// Everything this fork adds on top of google/boringssl lives under zig/.
// Zig requires build.zig at the package root, so this file only forwards to
// the real driver; see zig/README.md for the consumer and maintainer guide.
const impl = @import("zig/build.zig");

pub const build = impl.build;

/// Consumer helper: `@import("boringssl").link(mod, dep, .{ .ssl = true })`
/// (the import name is whatever your build.zig.zon calls this dependency).
pub const link = impl.link;
pub const LinkOptions = impl.LinkOptions;
