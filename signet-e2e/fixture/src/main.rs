//! Generate the local/CI Signet test stack for Minister's crypto-core e2e and
//! fixture jobs: dev mTLS PKI, a keystore DB sealed with the FROZEN test
//! master seed from prf-vectors.json, and env files for both sides.
//!
//! Usage: signet-e2e-fixture <out_dir> <prf-vectors.json> [signet_url]
//!
//! Emits into <out_dir> (wiped first — everything here is a throwaway test
//! fixture; the seed is public by design and the KEK is random per run):
//!   certs/ca.pem            trust root for both ends (CA key NOT retained)
//!   certs/server.pem/.key   Signet server cert (SANs: signet, localhost, 127.0.0.1)
//!   certs/client.pem/.key   Minister client cert (CN "minister" -> SIGNET_PRF_CLIENT_IDS)
//!   db/signet.db            keystore with the frozen seed sealed under the KEK
//!   signet.env              SIGNET_KEK + SIGNET_DEDUP_PUBKEY_PIN (+ allow-lists)
//!   minister.env            MINISTER_NULLIFIER_BACKEND=signet + MINISTER_SIGNET_*
//!   pk                      the derived pkS (must equal the frozen vector)
//!
//! NEVER point this at a production Signet volume: `seal_master_seed` refuses
//! if service keys already exist, and the seed here is a PUBLIC test vector.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use signet::db::Db;
use signet::dedup::seal_master_seed;
use signet::keystore::Kek;
use signet::prf::MASTER_SEED_LEN;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

fn main() {
    let usage = "usage: signet-e2e-fixture <out_dir> <prf-vectors.json> [signet_url]";
    let mut args = std::env::args().skip(1);
    let out_dir = args.next().unwrap_or_else(|| die(usage));
    let vectors_path = args.next().unwrap_or_else(|| die(usage));
    let signet_url = args.next().unwrap_or_else(|| "https://localhost:9443".to_string());
    let out = Path::new(&out_dir);

    // Wipe + recreate: the stack must be deterministic per run.
    if out.exists() {
        fs::remove_dir_all(out).expect("wipe out dir");
    }
    for sub in ["certs", "db"] {
        fs::create_dir_all(out.join(sub)).expect("create out dirs");
    }

    // --- Frozen test master seed (public fixture, never a production key) ---
    let raw = fs::read_to_string(&vectors_path).expect("read prf-vectors.json");
    let vectors: serde_json::Value = serde_json::from_str(&raw).expect("vectors JSON");
    let seed_bytes = hex::decode(
        vectors["master_seed_hex"]
            .as_str()
            .expect("master_seed_hex"),
    )
    .expect("master_seed_hex is hex");
    assert_eq!(seed_bytes.len(), MASTER_SEED_LEN, "frozen seed length");
    let mut seed = [0u8; MASTER_SEED_LEN];
    seed.copy_from_slice(&seed_bytes);
    let frozen_pk = vectors["public_key_b64url"]
        .as_str()
        .expect("public_key_b64url");

    // --- KEK (random per run; written next to the DB — test fixture only) ---
    let kek_hex = hex::encode(rand::random::<[u8; 32]>());
    let kek = Kek::from_encoded(&kek_hex).expect("KEK");

    // --- Seal the seed with Signet's own keystore code ---
    let db = Db::open(&out.join("db/signet.db")).expect("open keystore db");
    let pk = seal_master_seed(&db, &kek, &seed).expect("seal master seed");
    assert_eq!(
        pk, frozen_pk,
        "derived pkS does not match the frozen vector — key schedule drift"
    );

    // The compose path runs Signet as uid 10001 with the stack bind-mounted;
    // the ledger writes (dedup_entries + SQLite WAL) need the db dir and file
    // writable from inside the container. Throwaway test fixture — loose
    // permissions are fine here and nowhere else.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out.join("db"), fs::Permissions::from_mode(0o777))
            .expect("chmod db dir");
        fs::set_permissions(out.join("db/signet.db"), fs::Permissions::from_mode(0o666))
            .expect("chmod db file");
    }

    // --- Dev mTLS PKI (CA + server + Minister client, CN "minister") ---
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Minister Signet E2E CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
    write(out, "certs/ca.pem", &ca_cert.pem());

    let server_key = KeyPair::generate().expect("server key");
    let mut sp = CertificateParams::new(vec![]).expect("server params");
    sp.distinguished_name.push(DnType::CommonName, "signet");
    sp.subject_alt_names = vec![
        SanType::DnsName("signet".try_into().unwrap()),
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into()),
    ];
    sp.is_ca = IsCa::NoCa;
    sp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = sp
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server cert");
    write(out, "certs/server.pem", &server_cert.pem());
    write(out, "certs/server.key", &server_key.serialize_pem());

    let client_key = KeyPair::generate().expect("client key");
    let mut cp = CertificateParams::new(vec![]).expect("client params");
    cp.distinguished_name.push(DnType::CommonName, "minister");
    cp.is_ca = IsCa::NoCa;
    cp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = cp
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("sign client cert");
    write(out, "certs/client.pem", &client_cert.pem());
    write(out, "certs/client.key", &client_key.serialize_pem());

    // --- Env files ---
    write(out, "pk", &format!("{pk}\n"));
    write(
        out,
        "signet.env",
        &format!(
            "SIGNET_KEK={kek_hex}\n\
             SIGNET_DEDUP_PUBKEY_PIN={pk}\n\
             SIGNET_PRF_CLIENT_IDS=minister\n\
             SIGNET_ALLOWED_CLIENT_IDS=minister\n"
        ),
    );
    let abs = fs::canonicalize(out).expect("canonicalize out dir");
    let abs = abs.display();
    write(
        out,
        "minister.env",
        &format!(
            "MINISTER_NULLIFIER_BACKEND=signet\n\
             MINISTER_SIGNET_URL={signet_url}\n\
             MINISTER_SIGNET_CLIENT_CERT={abs}/certs/client.pem\n\
             MINISTER_SIGNET_CLIENT_KEY={abs}/certs/client.key\n\
             MINISTER_SIGNET_CA_CERT={abs}/certs/ca.pem\n\
             MINISTER_SIGNET_DEDUP_PUBKEY={pk}\n"
        ),
    );

    eprintln!("signet e2e stack written to {abs} (pkS = frozen vector, OK)");
}

fn write(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    fs::write(&path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}
