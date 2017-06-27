#TRUSTED 9c3350d19fe59f1f201c1ff2a73594646dfb4da0136d41e609c68757d4ae937343bef57c969ba842bea8b944efedb92f61b520e205aee3e8aa92a6e21fb9c5f700689fc8a9593977d80ed9b27c4e8811835fc52317b4ce8482938c83e9c54a36a21eafdf6ba2c27ed68b4e972c1439ec2942de496c85bb8bca8e481d8e01493f250ea6e8d9d20fc6633086a5f903e0295cff8cad4658fc66ccd7888e335d72bc2b0a4628b4d1194d7485ebdaab62ac06319cf4a6b3b2a794133f9abc2de5a7cb8309433314c859d13c3adfdd7d6d252f3fb9fac571c2260df22ddc7eb691934bd3966860d9742f27d1d3b3e4f71ca23bd82d85cf99dc4592cf674ad8179be735168151ed8252cef169f4e46332f493ea44416d3700c11d5a5bb184ab96c2dfb4d738573154a18f9c76b777615ef43ba1f2c6c2293404845c6aa7ee7d65f5049cc68241ca2a483c1c41528fe46f0cccca359931dec042844f65ec31afd247908b788733e30582b72cc572c21339188239fdeb41547076e0aacca77d4cfa6e66d9bb6ad38afe15d22175c0a460cee2427eb83b6efb36e576faae962b663b4a2353bb42e5b1b57821a1a79de371d9a026f6fd0338037a1f964932296a6f027ee5e058ea2686a73fbb145df385179f5aa9697cd6c89f111e5dd3d96c637af6a0a78d041e2f156b320137bc9599d79980c6e3e5157f02ff0859c11171228b314fbc8e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83528);

  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/07");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206"
  );
  script_bugtraq_id(
    71934,
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942
  );
  script_osvdb_id(
    116423,
    116790,
    116791,
    116792,
    116793,
    116794,
    116795,
    116796
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut14256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus42713");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus42717");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus42761");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus42784");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus42972");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus43046");

  script_name(english:"Cisco NX-OS OpenSSL Multiple Vulnerabilities (cisco-sa-20150310-ssl) (FREAK)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of NX-OS software that
is affected by multiple vulnerabilities in its bundled OpenSSL
library:

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A NULL pointer dereference flaw exists with
    dtls1_get_record() when handling DTLS messages. A remote
    attacker, using a specially crafted DTLS message, can
    cause a denial of service. (CVE-2014-3571)

  - A flaw exists with ECDH handshakes when using an ECDSA
    certificate without a ServerKeyExchange message. This
    allows a remote attacker to trigger a loss of forward
    secrecy from the ciphersuite. (CVE-2014-3572)

  - A flaw exists when accepting non-DER variations of
    certificate signature algorithms and signature encodings
    due to a lack of enforcement of matches between signed
    and unsigned portions. A remote attacker, by including
    crafted data within a certificate's unsigned portion,
    can bypass fingerprint-based certificate-blacklist
    protection mechanisms. (CVE-2014-8275)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A flaw exists when accepting DH certificates for client
    authentication without the CertificateVerify message.
    This allows a remote attacker to authenticate to the
    service without a private key. (CVE-2015-0205)

  - A memory leak occurs in dtls1_buffer_record()
    when handling a saturation of DTLS records containing
    the same number sequence but for the next epoch. This
    allows a remote attacker to cause a denial of service.
    (CVE-2015-0206)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150310-ssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd646a4f");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or workaround supplied by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag     = 0;
override = 0;
cbid     = FALSE;
n1kfix   = "5.2(1)SV3(1.4)";
n3kfix   = "Contact vendor";
n5kfix   = "Contact vendor";
n6kfix   = "Contact vendor";
n7kfix   = "Contact vendor";
n9kfix   = "7.0(3)I1(2)";

########################################
# Model 1k
########################################
if (model =~ "^1[0-9][0-9][0-9][0-9][vV]$")
{
  if(version == "4.0(4)SV1(1)"         ) {flag += 1; fix = nk1fix;}
  else if(version == "4.0(4)SV1(2)"    ) {flag += 1; fix = nk1fix;}
  else if(version == "4.0(4)SV1(3)"    ) {flag += 1; fix = nk1fix;}
  else if(version == "4.0(4)SV1(3a)"   ) {flag += 1; fix = nk1fix;}
  else if(version == "4.0(4)SV1(3b)"   ) {flag += 1; fix = nk1fix;}
  else if(version == "4.0(4)SV1(3c)"   ) {flag += 1; fix = nk1fix;}
  else if(version == "4.0(4)SV1(3d)"   ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV1(4)"    ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV1(4a)"   ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV1(4b)"   ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV1(5.1)"  ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV1(5.1a)" ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV1(5.2)"  ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV1(5.2b)" ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV2(1.1)"  ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV2(1.1a)" ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV2(2.1)"  ) {flag += 1; fix = nk1fix;}
  else if(version == "4.2(1)SV2(2.1a)" ) {flag += 1; fix = nk1fix;}
  else if(version == "5.2(1)SM1(5.1)"  ) {flag += 1; fix = nk1fix;}
  # Specifically from bug
  else if(version == "5.2(1)SV3(1.2)"  ) {flag += 1; fix = nk1fix;}
  cbid = "CSCut14256";
}
########################################
# Model 3k
########################################
else if (model =~ "^3[0-9][0-9][0-9]$")
{
  if(version == "5.0(3)U1(1)"       ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U1(1a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U1(1b)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U1(1d)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U1(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U1(2a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U2(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U2(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U2(2a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U2(2b)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U2(2c)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U2(2d)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U3(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U3(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U3(2a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U3(2b)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U4(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1b)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1c)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1d)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1e)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1f)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1g)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1h)" ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(1a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(4)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(4)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(5)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(6)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(4)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(5)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U4(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U4(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U4(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U5(1)"  ) {flag += 1; fix = n3kfix;}
  cbid = "CSCus43046";
}
########################################
# Model 5k
########################################
else if (model =~ "^5[0-9][0-9][0-9]$")
{
  if(version == "4.0(0)N1(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "4.0(0)N1(2)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "4.0(0)N1(2a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "4.0(1a)N1(1)" ) {flag += 1; fix = n5kfix;}
  else if(version == "4.0(1a)N1(1a)") {flag += 1; fix = n5kfix;}
  else if(version == "4.0(1a)N2(1)" ) {flag += 1; fix = n5kfix;}
  else if(version == "4.0(1a)N2(1a)") {flag += 1; fix = n5kfix;}
  else if(version == "4.1(3)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "4.1(3)N1(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "4.1(3)N2(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "4.1(3)N2(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "4.2(1)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "4.2(1)N2(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "4.2(1)N2(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(2)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(3)N1(1c)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(2)N2(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(2)N2(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(3)N2(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(3)N2(2)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(3)N2(2a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.0(3)N2(2b)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.1(3)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.1(3)N1(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.1(3)N2(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.1(3)N2(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.1(3)N2(1b)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.1(3)N2(1c)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(1a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(1b)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(2)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(2a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(3)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(4)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(5)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(6)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(7)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(8)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "5.2(1)N1(8a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N1(2)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N1(2a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(1b)" ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(2)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(3)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(4)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(5)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(0)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(1)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(2)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(3)N1(1)"  ) {flag += 1; fix = n5kfix;}
  cbid = "CSCus42713"; # This bug covers 5/6/7
  # There are various suggested work arounds, they require
  # disabling many features, it is not really apparent how
  # to check for them.
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}
########################################
# Model 6k
########################################
else if (model =~ "^6[0-9][0-9][0-9]$")
{
  if(version == "6.0(2)N1(2)"       ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N1(2a)" ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(1b)" ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(2)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(3)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(4)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(5)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(0)N1(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(1)N1(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(2)N1(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(3)N1(1)"  ) {flag += 1; fix = n6kfix;}
  cbid = "CSCus42713";
}
########################################
# Model 7k
########################################
else if (model =~ "^7[0-9][0-9][0-9]$")
{
  if(version == "4.1.(2)"       ) {flag += 1; fix = n7kfix;}
  else if(version == "4.1.(3)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "4.1.(4)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "4.1.(5)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "4.2.(2a)" ) {flag += 1; fix = n7kfix;}
  else if(version == "4.2(3)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "4.2(4)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "4.2(6)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "4.2(8)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.0(2a)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "5.0(3)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.0(5)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.1(1)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.1(1a)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "5.1(3)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.1(4)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.1(5)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.1(6)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.2(1)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.2(3a)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "5.2(4)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.2(5)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.2(7)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "5.2(9)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.0(1)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.0(2)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.0(3)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.0(4)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(1)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(2)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(3)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(4)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(4a)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(2)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(2a)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(6)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(6b)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8a)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8b)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(10)"  ) {flag += 1; fix = n7kfix;}
  # Specifically from bug
  else if(version == "5.2(8f)"         ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(7)"          ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8)S3"        ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8a)"         ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(11)"         ) {flag += 1; fix = n7kfix;}
  else if(version == "7.2(0)VX(0.9)"   ) {flag += 1; fix = n7kfix;}
  else if(version == "7.2(0.1)PR(0.1)" ) {flag += 1; fix = n7kfix;}
  else if(version == "7.3(0.9)"        ) {flag += 1; fix = n7kfix;}
  else if(version == "9.9(0)XS(0.1)"   ) {flag += 1; fix = n7kfix;}
  cbid = "CSCus42713";
  # Check to see if we can determine if SSL is enabled with LDAP
  if(flag)
  {
    flag = 0;
    buf  = cisco_command_kb_item("Host/Cisco/Config/show_ldap-server","show ldap-server");
    if(check_cisco_result(buf))
    {
      if(preg(multiline:TRUE, pattern:"enable-ssl", string:buf))
        flag += 1;
      else if(cisco_needs_enable(buf))
      {
        flag += 1;
        override = 1;
      }
    }
  }
}
########################################
# Model 9k
########################################
else if (model =~ "^9[0-9][0-9][0-9]$")
{
  if(version == "6.1(2)I2(1)"       ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(2)"  ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(2a)" ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(2b)" ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(3)"  ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I3(1)"  ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I3(2)"  ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I3(3)"  ) {flag += 1; fix = n9kfix;}
  else if(version == "11.0(1b)"     ) {flag += 1; fix = n9kfix;}
  else if(version == "11.0(1c)"     ) {flag += 1; fix = n9kfix;}
  # Specifically from bug
  else if(version == "7.0(3)I1(1.1)") {flag += 1; fix = n9kfix;}
  cbid = "CSCus42784";
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report = "";
    if(cbid) report += 
      '\n  Cisco bug ID      : ' + cbid;
    report +=
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra: cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
