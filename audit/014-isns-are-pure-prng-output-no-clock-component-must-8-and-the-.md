# 014. ISNs are raw output of a non-cryptographic PRNG: no clock component (MUST-8), and the state is recoverable from two observed ISNs (MUST-9)

| | |
|---|---|
| Severity | high |
| Category | security |
| Location | [src/tcp/mod.rs:782](../src/tcp/mod.rs#L782), [src/rand.rs:23](../src/rand.rs#L23), [src/tcp/listener.rs:239](../src/tcp/listener.rs#L239), [src/tcp/mod.rs:2594](../src/tcp/mod.rs#L2594), [src/stack.rs:520](../src/stack.rs#L520) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`random_seq_no` returns `rand.rand_u32()` from a 64-bit-state sPCG32. There is no clock term and no keyed hash of the 4-tuple. Each output exposes 32 contiguous state bits, so two observed ISNs recover the full state in under a second. After that every later ISN, ephemeral port, tsval offset, DNS transaction id and DHCP xid is predictable.

## Details

src/tcp/mod.rs:781
```rust
fn random_seq_no(rand: &mut Rand) -> TcpSeqNumber {
    TcpSeqNumber(rand.rand_u32() as i32)
}
```

src/rand.rs:29
```rust
let s = self.state.wrapping_mul(M).wrapping_add(A);
self.state = s;

let shift = 29 - (s >> 61);
(s >> shift) as u32
```

Given one output, the top 3 bits pick the shift (8 guesses) and the rest of the unknown state is the low `shift` bits plus a few top bits. A second output checks each candidate. About 2^32 work in total.

It is called from `connect` (src/tcp/mod.rs:2594) and `AcceptToken::start_syn_received` (src/tcp/listener.rs:239). The same generator also feeds ephemeral ports (src/stack.rs:502), tsval offsets (src/tcp/mod.rs:792), IPv4 fragment ids (src/fragmentation.rs), DNS transaction ids (src/dns.rs) and DHCP xids (src/iface/dhcpv4.rs:459). Outputs are easy to collect, and draws in between only add a small gap-guessing factor.

The public doc on `Stack::new` (src/stack.rs:520) says the seed "should be random, or at least different at every boot". That implies a good seed makes ISNs and ports unpredictable. It does not, once outputs reveal the state. The "non-cryptographic" note is only in the private `rand` module.

With no clock term, a new incarnation of a 4-tuple can also get an ISN below the previous incarnation's sequence space.

## Failure scenario

An attacker opens two connections to a xarxa listener and records the ISNs in the SYN|ACKs. It recovers the PRNG state offline in about 0.5 s. It then predicts the ISN of the next accepted connection and completes a blind spoofed handshake from a trusted IP, or predicts the ephemeral port and ISN of the device's next outgoing connection and injects RSTs or data.

## RFC reference

RFC 9293 §3.4.1: "A TCP implementation MUST use the above type of "clock" for clock-driven selection of initial sequence numbers (MUST-8), and SHOULD generate its initial sequence numbers with the expression: ISN = M + F(localip, localport, remoteip, remoteport, secretkey) ... (SHLD-1). F() MUST NOT be computable from the outside (MUST-9), or an attacker could still guess at sequence numbers from the ISN used for some other connection."

## Reproduction

Standalone C program with the exact constants from src/rand.rs (not a crate test):

```c
#define M 0xbb2efcec3c39611dULL
#define A 0x7590ef39ULL
static uint32_t out(uint64_t s){ unsigned shift = 29 - (s>>61); return (uint32_t)(s>>shift); }
static uint32_t next(uint64_t *st){ uint64_t s=*st*M+A; *st=s; return out(s); }
int main(int argc,char**argv){
  uint64_t st = 0x1234567890abcdefULL ^ (uint64_t)atoll(argv[1]);
  for(int i=0;i<5;i++) next(&st);
  uint32_t o1 = next(&st); uint64_t secret_after_o1 = st;
  uint32_t o2 = next(&st); uint32_t o3_true = next(&st);
  printf("observed ISNs: %08x %08x ; true next ISN %08x\n", o1,o2,o3_true);
  long found=0;
  #pragma omp parallel for reduction(+:found)
  for(int t=0;t<8;t++){ unsigned shift=29-t;
    uint64_t known = ((uint64_t)t<<61) | ((uint64_t)o1<<shift);
    for(uint64_t h=0;h<(1ULL<<t);h++) for(uint64_t l=0;l<(1ULL<<shift);l++){
      uint64_t s = known | (h<<(shift+32)) | l;
      if(out(s)!=o1) continue; uint64_t s2=s*M+A;
      if(out(s2)==o2){ uint64_t s3=s2*M+A;
        printf("candidate state %016llx (true %016llx) -> predicted next ISN %08x\n",(unsigned long long)s,(unsigned long long)secret_after_o1,out(s3)); found++; } } }
  printf("candidates: %ld\n",found);
}
```

`gcc -O3 -fopenmp -o pcg_recover pcg_recover.c && time ./pcg_recover 42`

```
observed ISNs: f77eec53 f4d06673 ; true next ISN a5634c32
candidate state c5fbbf762991fe17 (true d7fbbf762991fe17) -> predicted next ISN 32b1a619
candidate state c6fbbf762991fe17 (true d7fbbf762991fe17) -> predicted next ISN 0ac69864
candidate state cefbbf762991fe17 (true d7fbbf762991fe17) -> predicted next ISN 5634c324
candidate state d7fbbf762991fe17 (true d7fbbf762991fe17) -> predicted next ISN a5634c32
candidates: 4
real 0m0.549s
```

One more observed output leaves a single candidate.

## Suggested fix

Use RFC 6528: ISN = (clock in 4 µs units) + keyed hash (for example SipHash) of the 4-tuple, with the key drawn once from the user seed. Derive DNS ids, DHCP xids and ephemeral ports from a keyed function too, or from a CSPRNG. Keep the PCG for non-security uses only, and fix the `Stack::new` doc.
