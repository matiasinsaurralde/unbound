# Unbound Zero-Day Discovery — Findings Log

Target: NLnet Labs `unbound` (this repo). Goal: identify an exploit chain enabling
crash (DoS), RCE, cache poisoning, or similar, from first-principles code analysis.

Method: multi-agent adversarial audit. Approach families tracked below. Concrete
bugs are double-checked by adversarial agents before being marked confirmed.

Date started: 2026-07-22

---

## Approach Registry (families)

| ID | Family | Status | Notes |
|----|--------|--------|-------|
| F1 | Wire parsing / sldns (parse.c, wire2str, str2wire) memory safety | OPEN | |
| F2 | DNS msg parse/encode + dname + EDNS options | OPEN | |
| F3 | Cache handling & cache poisoning (services/cache, iter_scrub, respip, rrset) | OPEN | |
| F4 | Control/config/aux modules (remote.c, dnscrypt, subnet, dns64, cachedb) | OPEN | |

## Confirmed / Candidate Findings

(none yet)

## Blocked routes

(none yet)

## Round log

### Round 1 (in progress)
- F1 (sldns wire parsing), F2 (msgparse/edns), F3 (cache/scrub/poison), F4 (remote/config/dnscrypt/cachedb) fan-out launched.
- Root manual spot-checks (uncovered modules): validator NSEC3 parse (nsec3_get_salt/nextowner/has_type) — bounds checks correct; dns64 synthesize_aaaa — correct u-byte handling; val_sigcrypt canonicalize buffer bounds — correct; authzone rrset_add_rr alloc math — correct. No planted bug in these yet.

### Wave-2 candidate targets (uncovered so far)
- validator/ DNSSEC verify bypass (val_secalgo signature check, val_sigcrypt verify, val_nsec/val_neg proofs)
- util/netevent.c + services/outside_network.c + services/mesh.c (response matching, TCP/DoH/DoQ reassembly)
- util/data/dname.c, packed_rrset.c, msgencode.c
- ipsecmod, ipset, pythonmod/dynlibmod, cachedb/redis deserialize
