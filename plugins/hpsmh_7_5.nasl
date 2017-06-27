#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84923);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id(
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3523",
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8142",
    "CVE-2014-8275",
    "CVE-2014-9427",
    "CVE-2014-9652",
    "CVE-2014-9653",
    "CVE-2014-9705",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206",
    "CVE-2015-0207",
    "CVE-2015-0208",
    "CVE-2015-0209",
    "CVE-2015-0231",
    "CVE-2015-0232",
    "CVE-2015-0273",
    "CVE-2015-0285",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0290",
    "CVE-2015-0291",
    "CVE-2015-0292",
    "CVE-2015-0293",
    "CVE-2015-1787",
    "CVE-2015-2134",
    "CVE-2015-2301",
    "CVE-2015-2331",
    "CVE-2015-2348",
    "CVE-2015-2787"
  );
  script_bugtraq_id(
    68678,
    68742,
    68745,
    68747,
    71791,
    71833,
    71934,
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942,
    72505,
    72516,
    72539,
    72541,
    72701,
    73031,
    73037,
    73225,
    73226,
    73227,
    73228,
    73229,
    73230,
    73231,
    73232,
    73234,
    73235,
    73237,
    73238,
    73239,
    73431,
    73434,
    75961
  );
  script_osvdb_id(
    109216,
    109230,
    109231,
    109234,
    115011,
    116020,
    116020,
    116423,
    116621,
    116790,
    116791,
    116792,
    116793,
    116794,
    116795,
    116796,
    117467,
    118387,
    118582,
    118589,
    118817,
    119328,
    119614,
    119650,
    119673,
    119692,
    119693,
    119743,
    119755,
    119756,
    119757,
    119758,
    119759,
    119760,
    119761,
    119773,
    119774,
    125015
  );
  script_xref(name:"HP", value:"SSRT102109");
  script_xref(name:"HP", value:"HPSBMU03380");
  script_xref(name:"HP", value:"emr_na-c04746490");
  script_xref(name:"CERT", value:"243585");

  script_name(english:"HP System Management Homepage 7.3.x / 7.4.x < 7.5.0 Multiple Vulnerabilities (FREAK)");
  script_summary(english:"Checks version in the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is prior to
7.5.0. It is, therefore, affected by multiple vulnerabilities :

  - An flaw exists within the 'mod_deflate' module when
    handling highly compressed bodies. A remote attacker can
    exploit this, via a specially crafted request, to
    exhaust memory and CPU resources, resulting in a denial
    of service condition. (CVE-2014-0118)

  - The 'mod_status' module contains a race condition that
    can be triggered when handling the scoreboard. A remote
    attacker can exploit this to cause a denial of service,
    execute arbitrary code, or obtain sensitive credential
    information. (CVE-2014-0226)

  - The 'mod_cgid' module lacks a time out mechanism. A
    remote attacker can exploit this, via a specially
    crafted request, to cause child processes to linger
    indefinitely, filling up the scoreboard and resulting in
    a denial of service vulnerability. (CVE-2014-0231)

  - A flaw exists in WinNT MPM versions 2.4.1 to 2.4.9 when
    using the default AcceptFilter. An attacker can exploit
    this, via specially crafted requests. to create a memory
    leak, resulting in a denial of service condition.
    (CVE-2014-3523)

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A NULL pointer dereference flaw exists in the
    dtls1_get_record() function when handling DTLS messages.
    A remote attacker, using a specially crafted DTLS
    message, can cause a denial of service. (CVE-2014-3571)

  - A flaw exists with ECDH handshakes when using an ECDSA
    certificate without a ServerKeyExchange message. This
    allows a remote attacker to trigger a loss of forward
    secrecy from the ciphersuite. (CVE-2014-3572)

  - A use-after-free error exists in the
    'process_nested_data' function within
    'ext/standard/var_unserializer.re' due to improper
    handling of duplicate keys within the serialized
    properties of an object. A remote attacker, using a
    specially crafted call to the 'unserialize' method, can
    exploit this flaw to execute arbitrary code on the
    system. (CVE-2014-8142)

  - A flaw exists when accepting non-DER variations of
    certificate signature algorithms and signature encodings
    due to a lack of enforcement of matches between signed
    and unsigned portions. A remote attacker, by including
    crafted data within a certificate's unsigned portion,
    can bypass fingerprint-based certificate-blacklist
    protection mechanisms. (CVE-2014-8275)

  - An out-of-bounds read flaw in file 'cgi_main.c' exists
    when nmap is used to process an invalid file that begins
    with a hash character (#) but lacks a newline character.
    A remote attacker, using a specially crafted PHP file,
    can exploit this vulnerability to disclose memory
    contents, cause a denial of service, or possibly execute
    code. (CVE-2014-9427)

  - An out-of-bounds read error exists in the Fine Free File
    component that is bundled with PHP. A remote attacker
    can exploit this to cause a denial of service condition
    or the disclosure of sensitive information.
    (CVE-2014-9652)

  - A memory corruption issue exists in the Fine Free File
    component that is bundled with PHP. A remote attacker
    can exploit this to cause an unspecified impact.
    (CVE-2014-9653)

  - A heap buffer overflow condition exists in PHP in the
    enchant_broker_request_dict() function due to improper
    validation of user-supplied input. An attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2014-9705)

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
    (CVE-2015-0206)

  - A flaw exists in the DTLSv1_listen() function due to
    state being preserved in the SSL object from one
    invocation to the next. A remote attacker can exploit
    this, via crafted DTLS traffic, to cause a segmentation
    fault, resulting in a denial of service.
    (CVE-2015-0207)

  - A flaw exists in the rsa_item_verify() function due to
    improper implementation of ASN.1 signature verification.
    A remote attacker can exploit this, via an ASN.1
    signature using the RSA PSS algorithm and invalid
    parameters, to cause a NULL pointer dereference,
    resulting in a denial of service. (CVE-2015-0208)

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - A use-after-free memory error exists in the
    process_nested_data() function in 'var_unserializer.re'
    due to improper handling of duplicate numerical keys
    within the serialized properties of an object. A remote
    attacker, using a crafted unserialize method call, can
    exploit this vulnerability to execute arbitrary code.
    (CVE-2015-0231)

  - A flaw exists in the exif_process_unicode() function in
    'exif.c' that allows freeing an uninitialized pointer. A
    remote attacker, using specially crafted EXIF data in a
    JPEG image, can exploit this to cause a denial of
    service or to execute arbitrary code. (CVE-2015-0232)

  - A use-after-free flaw exists in the function
    php_date_timezone_initialize_from_hash() within the
    'ext/date/php_date.c' script. An attacker can exploit
    this to access sensitive information or crash
    applications linked to PHP. (CVE-2015-0273)

  - A flaw exists in the ssl3_client_hello() function due to
    improper validation of a PRNG seed before proceeding
    with a handshake, resulting in insufficient entropy and
    predictable output. This allows a man-in-the-middle
    attacker to defeat cryptographic protection mechanisms
    via a brute-force attack, resulting in the disclosure of
    sensitive information. (CVE-2015-0285)

  - An invalid read error exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - A flaw exists with the 'multiblock' feature in the
    ssl3_write_bytes() function due to improper handling of
    certain non-blocking I/O cases. This allows a remote
    attacker to cause failed connections or a segmentation
    fault, resulting in a denial of service. (CVE-2015-0290)

  - A NULL pointer dereference flaw exists when handling
    clients attempting to renegotiate using an invalid
    signature algorithm extension. A remote attacker can
    exploit this to cause a denial of service.
    (CVE-2015-0291)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)

  - A flaw exists in the ssl3_get_client_key_exchange()
    function when client authentication and an ephemeral
    Diffie-Hellman ciphersuite are enabled. This allows a
    remote attacker, via a ClientKeyExchange message with a
    length of zero, to cause a denial of service.
    (CVE-2015-1787)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to the lack of a unique token when performing
    sensitive actions via HTTP requests. (CVE-2015-2134)

  - A use-after-free error exists in the function
    phar_rename_archive() in file 'phar_object.c'. A remote
    attacker, by attempting to rename a phar archive to an
    already existing file name, can exploit this to cause
    a denial of service. (CVE-2015-2301)

  - A use-after-free error exists related to function
    'unserialize', which can allow a remote attacker to
    execute arbitrary code. Note that this issue is due to
    an incomplete fix for CVE-2014-8142. (CVE-2015-0231)

  - A filter bypass vulnerability exists due to a flaw in
    the move_uploaded_file() function in which pathnames are
    truncated when a NULL byte is encountered. This allows a
    remote attacker, via a crafted second argument, to
    bypass intended extension restrictions and create files
    with unexpected names. (CVE-2015-2348)

  - A user-after-free error exists in the
    process_nested_data() function. This allows a remote
    attacker, via a crafted unserialize call, to dereference
    already freed memory, resulting in the execution of
    arbitrary code. (CVE-2015-2787)");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04746490
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81e217d7");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) version 7.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/hp_smh");

# Only Linux and Windows are affected -- HP-UX is not mentioned
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os && "Linux" >!< os) audit(AUDIT_OS_NOT, "Windows or Linux", os);
}

port    = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt)) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.5';

if (
  version_alt =~ "^7\.[34]([^0-9]|$)" &&
  ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1
)
{
  source_line = get_kb_item("www/"+port+"/hp_smh/source");

  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;
  report +=
    '\n  Installed version : ' + version_alt +
    '\n  Fixed version     : ' + fixed_version +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xsrf:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
