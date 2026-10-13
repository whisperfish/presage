# libsignal service

A Rust crate that implements Signal's API for building Signal clients.

## Repositories and related libraries

- This library is hosted on github.com/whisperfish/libsignal-service-rs
- The main dependency is on github.com/signalapp/libsignal
- Whisperfish and Presage are the main consumers of this library:
  - Whisperfish is on Git*lab*: gitlab.com/whisperfish/whisperfish
  - Presage is on Git*hub*: github.com/whisperfish/presage

## Pull Request Descriptions

Keep them short. One sentence is fine. Say what's missing or not yet implemented;
don't recite the diff — the reviewer reads the code. The maintainers generally
enjoy short PR descriptions; a few lines should suffice.

Brief high-level protocol context is fine (e.g. "Signal moved from direct contact
sync to StorageService"). Link to upstream sources (Signal-Android, Signal-Desktop,
Signal-Server, or Signal's blog) when referencing protocol behaviour.

Avoid:
- file-by-file changelogs, line counts, "what lands here" lists
- protocol tutorials, step-by-step test or code narration, first-person journey notes
- backwards-compat reassurances ("zero behavior change…"), ritual closers ("happy to
discuss", "verified locally")
- ALL-CAPS headers, hardware/platform name-dropping, stacked-PR preambles

Good:

> Implement StorageService read API. Encryption and upload is left unimplemented.
> Signal-Android reference: [StorageServiceService.kt](https://github.com/signalapp/Signal-Android/blob/main/lib/network/...)

Bad:

> This transformative PR unlocks the full potential of our storage layer by leveraging
> synergistic crypto primitives. We introduce a paradigm-shifting module that empowers
> consumers to seamlessly decrypt server-side manifests. The existing `pub fn new()`
> remains untouched — zero behavior change for any existing caller, guaranteed.
>
> WHY THIS MATTERS: On resource-constrained platforms (RISC-V @ 100 MHz), race conditions
> in the keepalive timer can destabilize long-lived WebSockets. Verified locally.
> Happy to discuss. Smallest possible blast radius.

## Commit messages

The same goes for commit messages as goes for PR descriptions: keep them short.
Explain what is not clear from the patch itself.

Agents are not authors. If you are inclined to add a `Co-authored-by` annotation,
refrain from doing so, and use `Assisted-by` instead.

## Code Style

Generally, follow the patterns, or lack thereof, already present in the library.

Keep comments short. One or two lines is usually enough. The reviewer will read the code.

Regarding comments:
- **Don't narrate the code.** `strip_padding()` removes padding — the name already says so.
- **Don't spread docs across field + const + constructor.** Pick one place as the
  single source of truth and link to it (`See with_max_outstanding_keepalives()`).
- **Don't leave plan markers or TODO history in the code.** Git already records history.
- **Do document the "why", not the "how"**, when the reason is non-obvious. When obvious, do not write a comment.
- Doc comments document behaviour, not implementation.

Good:

```rust
/// Close if unacked keepalives exceed the threshold.
/// See `with_max_outstanding_keepalives` for tuning.
```

Bad:

```rust
/// Under the hood, we orchestrate a sophisticated HKDF-SHA256 key-derivation pipeline
/// (info string: "20240801_SIGNAL_STORAGE_SERVICE_MANIFEST_" + version) feeding into
/// AES-256-GCM with 12-byte nonce prepended and 16-byte tag appended. The caller's
/// existing strip_padding() gracefully removes the trailing 0x80 ISO7816 pad, leaving
/// pristine protobuf bytes ready for the envelope pipeline. Our test suite validates
/// the full downstream flow end-to-end.
```
