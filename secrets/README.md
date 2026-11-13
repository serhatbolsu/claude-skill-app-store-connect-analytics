# secrets/ (gitignored, except this README)

Put your App Store Connect API private key here:

    secrets/AuthKey_<KEY_ID>.p8

then `chmod 600 secrets/AuthKey_<KEY_ID>.p8`.

Git ignores everything in this folder except this README, plus every `*.p8` file anywhere in
the repo. Apple lets you download a `.p8` only once. Keep a backup in your password manager. If
it leaks, revoke the key in App Store Connect → Users and Access → Integrations.

You can also keep the key outside the repo at `~/.appstoreconnect/private_keys/AuthKey_<KEY_ID>.p8`
(Apple's tools look there too), or set `ASC_PRIVATE_KEY_PATH` in `.env`.
