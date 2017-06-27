#TRUSTED 9bfb1c8a53035c3cff4ccfe2d4f6225b4149db03ab019b629005d2a47f7a40b3d8f074f43229b721ca1f4932ba693cac2317edb42c98ac3b846a45fa0e90af03850a65ad4b3b5f2bca831e895445f9e30ac1bffca910286a2aa7907b1487ad0c6db0a34f1ce745b8545843e5661fd4a8e2cfe07b5d0d5d0af50cd0aa812ae6e180b1970acebbc2e65175a07c8217c22985e40245cfd93af8b98196794e199753b6aa978e8b1c704f8f53b53da9dcaaa3af246acf76e772ae7628fcc1ee55965d8b22e5cf8f4035fdb0ffca061c6247335870f7cabbeafe455f48f381a1e0dd3406efa62b789c08178e8974be19f720a7458859c427e99d8ddda6647dae1d7694bd1551f201b7b8bc28bf857fa2760777f529c67638f99074b39ca550c49967544609cadbf2520aca9d285ecc472a5dbbd6a25199a483ad528cb78797c8a6305dbaeb97be3275031252f9705ec2a5c1d4c7256121cafdabe34bf61f843362ef8ac7d57fb9a7467cd012b94f47d34c0f6ffc4e013d2d94ce09aef49fc424d7e834d70b4316690f6aa413feb286c68180a530a246e6c73d76cc30fd42e3bcbdc13cddebbe0f14f877f1e94188a0b738b8fabc8fc31124964827698191a300eab21b29ec42c9e2ffc4fc0ca98386666097bd2ad5e2688ce347e20195e32df728776ec70dead58fb89cfbfff5a811a5b21aa729d99369df0d117cbd0f1d6f8f7ce8c8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82912);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205"
  );
  script_bugtraq_id(71934, 71935, 71936, 71939, 71941, 71942);
  script_osvdb_id(116423, 116790, 116792, 116794, 116795,116796);
  script_xref(name:"JSA", value:"JSA10679");
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10679) (FREAK)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by the following vulnerabilities related to
OpenSSL :

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

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

Note that these issues only affects devices with J-Web or the SSL
service for JUNOScript enabled.");

  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10679");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10679.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3'] = '12.3R10';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.2'] = '13.2R8';
fixes['13.3'] = '13.3R6';
fixes['14.1'] = '14.1R5';
fixes['14.2'] = '14.2R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management http(s)? interface", # J-Web
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }
  if (override)
    audit(AUDIT_HOST_NOT,
      'affected because J-Web and SSL Service for JUNOScript (XNM-SSL) are not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
