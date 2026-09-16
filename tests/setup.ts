/**
 * Runs before every test file (`vitest.config.ts` `setupFiles`).
 *
 * The known-values directory configuration is pinned to no directories, so
 * the global registry never reads the machine's `~/.known-values`; the
 * envelope and provenance-mark tags and summarisers are registered, as the
 * reference's tests call `bc_envelope::register_tags()` and
 * `provenance_mark::register_tags()`.
 */
import { DirectoryConfig, setDirectoryConfig } from "@blockchaincommons/known-values";
import { registerTags } from "@blockchaincommons/provenance-mark";

setDirectoryConfig(new DirectoryConfig());
registerTags();
