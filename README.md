# event-counter

Tracks key presses and mouse inputs, displaying the count in a minimal UI.
The count resets upon starting a new game in Mirror's Edge.

## Requirements

- For Windows machines

## Installation

Download and run the `event-counter.exe` file from the latest
[Releases](https://github.com/SeungKang/event-counter/releases).

You may need to set an exclusion for the exe file, or else Windows
Defender will probably flag and delete it. Refer to the
[Windows documentation][windows-exclusion] for more information.

[windows-exclusion]: https://support.microsoft.com/en-us/windows/add-an-exclusion-to-windows-security-811816c0-4dfd-af4a-47e4-c301afe13b26

## Verification

The executable file found under Releases was signed using Sigstore's `cosign`
tool. You can use `cosign` to verify the file's provenance, confirming it was
built by GitHub Actions and hasn't been tampered with. Receiving a "Verified OK"
output provides a cryptographic attestation that this file came from GitHub
Actions.

1. Install cosign https://docs.sigstore.dev/system_config/installation/
2. Download `event-counter.exe` and `cosign.bundle` from Releases
3. Run the command below to verify. Note: Replace NAME-OF-RELEASE with the release # from GitHub.

```console
$ cosign verify-blob path/to/event-counter.exe \
  --bundle path/to/cosign.bundle \
  --certificate-identity=https://github.com/SeungKang/event-counter/.github/workflows/build.yaml@refs/tags/NAME-OF-RELEASE \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
```

When it completes you should receive the following output:

```console
Verified OK
```
