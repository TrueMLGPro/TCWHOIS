<p><a href="https://android-arsenal.com/details/1/7176"><img src="https://img.shields.io/badge/Android%20Arsenal-TCWHOIS-blue.svg?style=for-the-badge" alt="Android Arsenal"></a> <a href="https://jitpack.io/#TrueMLGPro/TCWHOIS"><img src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fjitpack.io%2Fapi%2Fbuilds%2Fcom.github.TrueMLGPro%2FTCWHOIS%2Flatest&query=%24.version&label=JitPack&style=for-the-badge&color=lightgreen" alt="JitPack"></a>

> [!NOTE]
> Code from this library is going to be reused in the [AndroidNetworkTools](https://github.com/TrueMLGPro/AndroidNetworkTools) library.

# TCWHOIS

A small library which allows you to check Whois records of any domain.

## Installation

**Step 1.** Add the JitPack repository to your build file

Add it in your root build.gradle at the end of repositories:

```gradle
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

**Step 2.** Add the dependency

```gradle
dependencies {
    implementation 'com.github.TrueMLGPro:TCWHOIS:<commit_hash>'
}
```

## Usage

Sync lookup (call off the main thread - it does network I/O):

```java
TCWHOIS whoisClient = new TCWHOIS();
String whoisResult = whoisClient.getWhois(domainName); // Defaults to WhoisClient.DEFAULT_HOST
// String whoisResult = whoisClient.getWhois(domainName, tldCode);
textView.setText(whoisResult);
```

Non-blocking async lookup (no need to set up a background worker thread):

```java
TCWHOIS.getWhoisAsync(domainName, tldCode, new TCWHOIS.WhoisCallback() {
    @Override
    public void onResult(final String data) {
        runOnUiThread(() -> textView.setText(data));
    }

    @Override
    public void onError(Exception e) {
        Log.e(TAG, "Whois lookup failed", e);
    }
});
// Or without a TLD: TCWHOIS.getWhoisAsync(domainName, callback);
```

Parsed fields:

```java
String registryId = whoisClient.getRegistryDomainId(domainName);
String registrarUrl = whoisClient.getRegistrarUrl(domainName);
String updateRaw = whoisClient.getUpdateDateRaw(domainName);
String updateFormatted = whoisClient.getUpdateDayFormatted(domainName);
String creationRaw = whoisClient.getCreationDateRaw(domainName);
String creationFormatted = whoisClient.getCreationDayFormatted(domainName);
```

Call `TCWHOIS.shutdown()` only when the process no longer needs async lookups (it permanently shuts down the shared executor).

> **Notes**
> - Synchronous methods do network I/O, so call them off the main thread or use `getWhoisAsync`.
> - Use `domainname.suffix` form (`google.com`, no `www` or other subdomain).
> - Field parsers expect `.com`-style responses and return a "Domain not Found" message when parsing fails.
> - Not all TLDs are tested - please open an issue if one fails.

<details>
<summary>Supported TLD codes</summary>

```
ac, ad, ae, aer, af, ag, ai, al, am, as, asi, at, au, aw, ax, az, ba, bar, be, ber, bes, bg, bi, biz, bj, bo, br, br., bt, bw, by, bz, bzh, ca, cat, cc, cd, ceo, cf, ch, ci, ck, cl, clo, clu, cn, cn., co, co., com, coo, cx, cy, cz, de, dk, dm, dz, ec, edu, ee, eg, es, eu, eu., eus, fi, fo, fr, gb, gb., qc., ge, gg, gi, gl, gm, gov, gr, gs, gy, ham, hip, hk, hm, hn, hos, hr, ht, hu, hu., id, ie, il, im, in, inf, ing, ink, int, io, iq, ir, is, it, je, job, jp, ke, kg, ki, kr, kz, la, li, lon, lt, lu, lv, ly, ma, mc, md, me, mg, mil, mk, ml, mo, mob, ms, mt, mu, mus, mx, my, mz, na, nam, nc, net, nf, ng, nl, no, no., nu, nz, om, ong, ooo, org, par, pe, pf, pic, pl, pm, pr, pre, pro, pt, pub, pw, qa, re, ro, rs, ru, sa, sa., sb, sc, se, se., sg, sh, si, sk, sm, st, so, su, sx, sy, tc, tel, tf, th, tj, tk, tl, tm, tn, to, top, tp, tr, tra, tw, tv, tz, ua, ug, uk, uk., ac., gov, us, us., uy, uy., uz, va, vc, ve, vg, vu, wan, wf, wik, ws, xxx, xyz, yu, za.
```

</details>

## Result

TCWHOIS library returns results in string form.

**Sample**

    Domain Name: GOOGLE.COM
    Registry Domain ID: 2138514_DOMAIN_COM-VRSN
    Registrar WHOIS Server: whois.markmonitor.com
    Registrar URL: http://www.markmonitor.com
    Updated Date: 2018-02-21T18:36:40Z
    Creation Date: 1997-09-15T04:00:00Z
    Registry Expiry Date: 2020-09-14T04:00:00Z
    Registrar: MarkMonitor Inc.
    Registrar IANA ID: 292
    Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
    Registrar Abuse Contact Phone: +1.2083895740
    Domain Status: clientDeleteProhibited
    https://icann.org/epp#clientDeleteProhibited
    Domain Status: clientTransferProhibited
    https://icann.org/epp#clientTransferProhibited
    Domain Status: clientUpdateProhibited
    https://icann.org/epp#clientUpdateProhibited
    Domain Status: serverDeleteProhibited
    https://icann.org/epp#serverDeleteProhibited
    Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
    Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
    Name Server: NS1.GOOGLE.COM
    Name Server: NS2.GOOGLE.COM
    Name Server: NS3.GOOGLE.COM
    Name Server: NS4.GOOGLE.COM
    DNSSEC: unsigned
    URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/

    For more information on Whois status codes, please visit https://icann.org/epp

    NOTICE: The expiration date displayed in this record is the date the
    registrar's sponsorship of the domain name registration in the registry is
    currently set to expire. This date does not necessarily reflect the expiration
    date of the domain name registrant's agreement with the sponsoring
    registrar. Users may consult the sponsoring registrar's Whois database to
    view the registrar's reported date of expiration for this registration.

## Credit

Created by [@100rabhkr](https://github.com/100rabhkr) for [The Collective Web](https://thecollectiveweb.com).
