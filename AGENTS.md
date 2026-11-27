# presage

High-level batteries included library that lets you interact with the Signal Messenger service.

## Repositories and related libraries

- The main dependencies are (ours) github.com/whisperfish/libsignal-service-rs and (official) github.com/signalapp/libsignal

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

- Generally, follow the patterns, or lack thereof, already present in the library.
- Default to no comments. Add one only when the *why* isn't obvious (protocol quirk, server behaviour, workaround). One line.
- Never restate the code, narrate the change ("now uses gRPC"), or reference the task/PR/conversation.
- No doc comments that repeat the item name; public API docs short and factual.
- No banner/divider comments, no TODO essays.
- **Don't narrate the code.** `strip_padding()` removes padding — the name already says so.
- **Don't spread docs across field + const + constructor.** Pick one place as the single source of truth and link to it (`See with_max_outstanding_keepalives()`).
