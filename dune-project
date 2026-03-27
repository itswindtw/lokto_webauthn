(lang dune 3.21)

(name aiyu_webauthn)

(generate_opam_files true)

(package
  (name aiyu_webauthn)
  (depends
    ocaml
    yojson
    base64
    digestif
    mirage-crypto-rng
    x509
    aiyu_cbor
    (hex :with-test)
    (alcotest :with-test)
    (ocaml-lsp-server :with-dev-setup)
    (ocamlformat :with-dev-setup)))

(pin
  (url "git+https://github.com/itswindtw/aiyu_cbor")
  (package
    (name aiyu_cbor)))
