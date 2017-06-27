#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96337);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id(
    "CVE-2012-0876",
    "CVE-2012-6702",
    "CVE-2015-1283",
    "CVE-2016-0718",
    "CVE-2016-0719",
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-4472",
    "CVE-2016-5300",
    "CVE-2016-6153",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6305",
    "CVE-2016-6306",
    "CVE-2016-6307",
    "CVE-2016-6308",
    "CVE-2016-6309",
    "CVE-2016-7103",
    "CVE-2016-7052"
  );
  script_bugtraq_id(
    52379,
    75973,
    90729,
    91081,
    91159,
    91319,
    91483,
    91528,
    91546,
    92117,
    92557,
    92628,
    92630,
    92982,
    92984,
    92987,
    93149,
    93150,
    93151,
    93152,
    93153,
    93171,
    93177
  );
  script_osvdb_id(
    80892,
    122039,
    138680,
    139313,
    139342,
    139471,
    140838,
    142095,
    142096,
    143021,
    143259,
    143309,
    143387,
    143388,
    143389,
    143392,
    144680,
    144687,
    144688,
    144689,
    144690,
    144804,
    144805,
    148978
  );

  script_name(english:"Tenable Passive Vulnerability Scanner 5.x < 5.2.0 Multiple Vulnerabilities (SWEET32)");
  script_summary(english:"Checks the PVS version.");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Tenable Passive Vulnerability Scanner (PVS) installed
on the remote host is 5.x < 5.2.0. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple denial of service vulnerabilities exist in
    Expat within file xmlparse.c due to a logical error in
    hash computations. An unauthenticated, remote attacker
    can exploit these, via a specially crafted XML file
    containing many identifiers with the same value, to
    cause the service to exhaust CPU resources.
    (CVE-2012-0876, CVE-2016-5300)

  - A flaw exists in the generate_hash_secret_salt()
    function in file lib/xmlparse.c within Expat due to the
    generation of non-random output by the PRNG. An
    unauthenticated, remote attacker can exploit this to
    more easily predict the PRNG output. (CVE-2012-6702)

  - Multiple buffer overflow conditions exist within Expat,
    specifically in the XML_GetBuffer() function in file
    lib/xmlparse.c, due to improper validation of
    user-supplied input when handling compressed XML
    content. An unauthenticated, remote attacker can exploit
    these to execute arbitrary code. (CVE-2015-1283,
    CVE-2016-4472)

  - Multiple buffer overflow conditions exist within the
    Expat XML parser when handling malformed input documents
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0718, CVE-2016-0719)

  - Multiple integer overflow conditions exist in s3_srvr.c,
    ssl_sess.c, and t1_lib.c due to improper use of pointer
    arithmetic for heap-buffer boundary checks. An
    unauthenticated, remote attacker can exploit these to
    cause a denial of service. (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    dsa_sign_setup() function in dsa_ossl.c due to a failure
    to properly ensure the use of constant-time operations.
    An unauthenticated, remote attacker can exploit this,
    via a timing side-channel attack, to disclose DSA key
    information. (CVE-2016-2178)

  - A denial of service vulnerability exists in the DTLS
    implementation due to a failure to properly restrict the
    lifetime of queue entries associated with unused
    out-of-order messages. An unauthenticated, remote
    attacker can exploit this, by maintaining multiple
    crafted DTLS sessions simultaneously, to exhaust memory.
    (CVE-2016-2179)

  - An out-of-bounds read error exists in the X.509 Public
    Key Infrastructure Time-Stamp Protocol (TSP)
    implementation. An unauthenticated, remote attacker can
    exploit this, via a crafted time-stamp file that is
    mishandled by the 'openssl ts' command, to cause
    denial of service or to disclose sensitive information.
    (CVE-2016-2180)

  - A denial of service vulnerability exists in the
    Anti-Replay feature in the DTLS implementation due to
    improper handling of epoch sequence numbers in records.
    An unauthenticated, remote attacker can exploit this,
    via spoofed DTLS records, to cause legitimate packets to
    be dropped. (CVE-2016-2181)

  - An overflow condition exists in the BN_bn2dec() function
    in bn_print.c due to improper validation of
    user-supplied input when handling BIGNUM values. An
    unauthenticated, remote attacker can exploit this to
    crash the process. (CVE-2016-2182)

  - A vulnerability exists, known as SWEET32, in the 3DES
    and Blowfish algorithms due to the use of weak 64-bit
    block ciphers by default. A man-in-the-middle attacker
    who has sufficient resources can exploit this
    vulnerability, via a 'birthday' attack, to detect a
    collision that leaks the XOR between the fixed secret
    and a known plaintext, allowing the disclosure of the
    secret text, such as secure HTTPS cookies, and possibly
    resulting in the hijacking of an authenticated session.
    (CVE-2016-2183)

  - An flaw exists in SQLite due to the use of insecure
    temporary directories. A local attacker can exploit this
    to cause a denial of service condition or possibly have
    other more severe impact. (CVE-2016-6153)

  - A flaw exists in the tls_decrypt_ticket() function in
    t1_lib.c due to improper handling of ticket HMAC
    digests. An unauthenticated, remote attacker can exploit
    this, via a ticket that is too short, to crash the
    process, resulting in a denial of service.
    (CVE-2016-6302)

  - An integer overflow condition exists in the
    MDC2_Update() function in mdc2dgst.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2016-6303)

  - A flaw exists in the ssl_parse_clienthello_tlsext()
    function in t1_lib.c due to improper handling of overly
    large OCSP Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)

  - A flaw exists in the SSL_peek() function in
    rec_layer_s3.c due to improper handling of empty
    records. An unauthenticated, remote attacker can exploit
    this, by triggering a zero-length record in an SSL_peek
    call, to cause an infinite loop, resulting in a denial
    of service condition. (CVE-2016-6305)

  - An out-of-bounds read error exists in the certificate
    parser that allows an unauthenticated, remote attacker
    to cause a denial of service via crafted certificate
    operations. (CVE-2016-6306)

  - A denial of service vulnerability exists in the
    state-machine implementation due to a failure to check
    for an excessive length before allocating memory. An
    unauthenticated, remote attacker can exploit this, via a
    crafted TLS message, to exhaust memory resources.
    (CVE-2016-6307)

  - A denial of service vulnerability exists in the DTLS
    implementation due to improper handling of excessively
    long DTLS messages. An unauthenticated, remote attacker
    can exploit this, via a crafted DTLS message, to exhaust
    available memory resources. (CVE-2016-6308)

  - A remote code execution vulnerability exists in the
    read_state_machine() function in statem.c due to
    improper handling of messages larger than 16k. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted message, to cause a use-after-free
    error, resulting in a denial of service condition or
    possibly the execution of arbitrary code.
    (CVE-2016-6309)

  - A cross-site scripting (XSS) vulnerability exists within
    the JQuery UI dialog() function due to improper
    validation of input to the 'closeText' parameter before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-7103)

  - A denial of service vulnerability exists in x509_vfy.c
    due to improper handling of certificate revocation lists
    (CRLs). An unauthenticated, remote attacker can exploit
    this, via a specially crafted CRL, to cause a NULL
    pointer dereference, resulting in a crash of the
    service. (CVE-2016-7052)

  - An unspecified cross-site scripting (XSS) vulnerability
    exists in the web interface due to improper validation
    of input before returning it to users. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (VulnDB 148978)");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2016-20");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/products/passive-vulnerability-scanner");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Passive Vulnerability Scanner version 5.2.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:pvs");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies(
    "os_fingerprint.nasl",
    "pvs_installed_win.nbin",
    "pvs_installed_nix.nbin",
    "pvs_installed_macosx.nbin"
  );
 script_require_keys("Host/OS", "Host/pvs_installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

pvs_installed = get_kb_item_or_exit("Host/pvs_installed");
os = get_kb_item_or_exit("Host/OS");

if ('windows' >< tolower(os))
{
  version = get_kb_item_or_exit("SMB/PVS/Version");
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;
}
else
{
  # linux KB entry
  version = get_kb_item("Host/PVS/Version");
  # If that's not set, try Mac
  if (empty_or_null(version))
  {
    install = get_single_install(
      app_name:"Tenable Passive Vulnerability Scanner",
      exit_if_unknown_ver:TRUE
    );
    version = install['version'];
  }
  port = 0;
}

app_name = "Tenable PVS";
fixed_version = '5.2.0';

# Affects 5.x < 5.2.0
if (version !~ "^5\.[01]\.")
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
}

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

report =
  '\n  Application       : ' + app_name +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fixed_version +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xss:TRUE);
