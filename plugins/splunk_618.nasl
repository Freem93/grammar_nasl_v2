#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83992);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-0207",
    "CVE-2015-0208",
    "CVE-2015-0209",
    "CVE-2015-0285",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0290",
    "CVE-2015-0291",
    "CVE-2015-0292",
    "CVE-2015-0293",
    "CVE-2015-1787"
  );
  script_bugtraq_id(
    71936,
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
    73239
  );
  script_osvdb_id(
    116794,
    118817,
    119328,
    119614,
    119673,
    119692,
    119743,
    119755,
    119756,
    119757,
    119758,
    119759,
    119760,
    119761
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Splunk Enterprise 5.0.x < 5.0.13 / 6.0.x < 6.0.9 / 6.1.x < 6.1.8 OpenSSL Vulnerabilities (FREAK)");
  script_summary(english:"Checks the version of Splunk Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Splunk Enterprise hosted on the
remote web server is 5.0.x prior to 5.0.13, 6.0.x prior to 6.0.9, or 
6.1.x prior to 6.1.4. It is, therefore, affected by the following 
vulnerabilities related to the included OpenSSL library :

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

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

  - A flaw exists in the ssl3_client_hello() function due to
    improper validation of a PRNG seed before proceeding
    with a handshake, resulting in insufficient entropy and
    predictable output. This allows a man-in-the-middle
    attacker to defeat cryptographic protection mechanisms
    via a brute-force attack, resulting in the disclosure of
    sensitive information. (CVE-2015-0285)

  - An invalid read flaw exists in the ASN1_TYPE_cmp()
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

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAN4P");
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/secadv_20150319.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk Enterprise 5.0.13 / 6.0.9 / 6.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
fix = FALSE;

install_url = build_url(qs:dir, port:port);

# Affected : 5.0.x < 5.0.13
if (ver =~ "^5\.0($|[^0-9])")
  fix = '5.0.13';

# Affected : 6.0.x < 6.0.9
if (ver =~ "^6\.0($|[^0-9])")
  fix = '6.0.9';

# Affected : 6.1.x < 6.1.8
if (ver =~ "^6\.1($|[^0-9])")
  fix = '6.1.8';

if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
