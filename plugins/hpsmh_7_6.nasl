#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94654);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id(
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2107",
    "CVE-2016-2109",
    "CVE-2016-3739",
    "CVE-2016-4070",
    "CVE-2016-4071",
    "CVE-2016-4072",
    "CVE-2016-4342",
    "CVE-2016-4343",
    "CVE-2016-4393",
    "CVE-2016-4394",
    "CVE-2016-4395",
    "CVE-2016-4396",
    "CVE-2016-4537",
    "CVE-2016-4538",
    "CVE-2016-4539",
    "CVE-2016-4540",
    "CVE-2016-4541",
    "CVE-2016-4542",
    "CVE-2016-4543",
    "CVE-2016-5385",
    "CVE-2016-5387",
    "CVE-2016-5388"
  );
  script_bugtraq_id(
    85800,
    85801,
    85993,
    87940,
    89154,
    89179,
    89744,
    89757,
    89760,
    89844,
    90172,
    90173,
    90174,
    90726,
    91816,
    91818,
    91821,
    93961
  );
  script_osvdb_id(
    134031,
    134037,
    136483,
    136484,
    136486,
    137577,
    137781,
    137782,
    137783,
    137784,
    137896,
    137898,
    137899,
    138663,
    141667,
    141669,
    141670,
    146381,
    146382,
    146384,
    146385
  );
  script_xref(name:"CERT", value:"797896");
  script_xref(name:"IAVA", value:"2017-A-0010");
  script_xref(name:"IAVB", value:"2016-B-0160");
  script_xref(name:"EDB-ID", value:"39645");
  script_xref(name:"EDB-ID", value:"39653");
  script_xref(name:"EDB-ID", value:"39768");
  script_xref(name:"HP", value:"HPSBMU03653");
  script_xref(name:"HP", value:"emr_na-c05320149");
  script_xref(name:"HP", value:"PSRT110145");
  script_xref(name:"HP", value:"PSRT110263");
  script_xref(name:"HP", value:"PSRT110115");
  script_xref(name:"HP", value:"PSRT110116");
  script_xref(name:"TRA", value:"TRA-2016-32");
  script_xref(name:"ZDI", value:"ZDI-16-587");

  script_name(english:"HP System Management Homepage < 7.6 Multiple Vulnerabilities (HPSBMU03653) (httpoxy)");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of HP System Management Homepage
(SMH) hosted on the remote web server is prior to 7.6. It is,
therefore, affected by the following vulnerabilities :

  - A heap buffer overflow condition exists in OpenSSL in
    the EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in OpenSSL in
    the EVP_EncryptUpdate() function within file
    crypto/evp/evp_enc.c that is triggered when handling a
    large amount of input data after a previous call occurs
    to the same function with a partial block. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - Multiple flaws exist OpenSSL in the
    aesni_cbc_hmac_sha1_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha1.c and the
    aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - Multiple unspecified flaws exist in OpenSSL in the d2i
    BIO functions when reading ASN.1 data from a BIO due to
    invalid encoding causing a large allocation of memory.
    An unauthenticated, remote attacker can exploit these to
    cause a denial of service condition through resource
    exhaustion. (CVE-2016-2109)

  - A certificate validation bypass vulnerability exists in
    cURL and libcurl due to improper validation of TLS
    certificates. A man-in-the-middle attacker can exploit
    this, via a spoofed certificate that appears valid, to
    disclose or manipulate transmitted data. (CVE-2016-3739)

  - An integer overflow condition exists in PHP in the
    php_raw_url_encode() function within file
    ext/standard/url.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact.
    (CVE-2016-4070)
    
  - A flaw exists in PHP in the php_snmp_error() function
    within file ext/snmp/snmp.c that is triggered when
    handling format string specifiers. An unauthenticated,
    remote attacker can exploit this, via a crafted SNMP
    object, to cause a denial of service or to execute
    arbitrary code. (CVE-2016-4071)

  - An invalid memory write error exists in PHP when
    handling the path of phar file names that allows an
    attacker to have an unspecified impact. (CVE-2016-4072)

  - A remote code execution vulnerability exists in PHP in
    phar_object.c due to improper handling of zero-length
    uncompressed data. An unauthenticated, remote attacker
    can exploit this, via a specially crafted TAR, ZIP, or
    PHAR file, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-4342)

  - A remote code execution vulnerability exists in PHP in
    the phar_make_dirstream() function within file
    ext/phar/dirstream.c due to improper handling of
    ././@LongLink files. An unauthenticated, remote attacker
    can exploit this, via a specially crafted TAR file, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-4343)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-4393)

  - An unspecified HTTP Strict Transport Security (HSTS)
    bypass vulnerability exists that allows authenticated,
    remote attackers to disclose sensitive information.
    (CVE-2016-4394)

  - A remote code execution vulnerability exists due to an
    overflow condition in the mod_smh_config.so library
    caused by improper validation of user-supplied input
    when parsing the admin-group parameter supplied to the
    /proxy/SetSMHData endpoint. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-4395)

  - A remote code execution vulnerability exists due to an
    overflow condition in the mod_smh_config.so library
    caused by improper validation of user-supplied input
    when parsing the TKN parameter supplied to the
    /Proxy/SSO endpoint. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-4396)

  - An out-of-bounds read error exists in PHP in the
    php_str2num() function in bcmath.c when handling
    negative scales. An unauthenticated, remote attacker can
    exploit this, via a crafted call, to cause a denial of
    service condition or the disclosure of memory contents.
    (CVE-2016-4537)

  - A flaw exists in PHP the bcpowmod() function in bcmath.c
    due to modifying certain data structures without
    considering whether they are copies of the _zero_,
    _one_, or _two_ global variables. An unauthenticated,
    remote attacker can exploit this, via a crafted call, to
    cause a denial of service condition. (CVE-2016-4538)

  - A flaw exists in PHP in the xml_parse_into_struct()
    function in xml.c when handling specially crafted XML
    contents. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2016-4539)

  - Multiple out-of-bounds read errors exist in PHP within
    file ext/intl/grapheme/grapheme_string.c when handling
    negative offsets in the zif_grapheme_stripos() and
    zif_grapheme_strpos() functions. An unauthenticated,
    remote attacker can exploit these issues to cause a
    denial of service condition or disclose memory contents.
    (CVE-2016-4540, CVE-2016-4541)

  - A flaw exists in PHP in the exif_process_IFD_TAG()
    function in exif.c due to improper construction of
    spprintf arguments. An unauthenticated, remote attacker
    can exploit this, via crafted header data, to cause an
    out-of-bounds read error, resulting in a denial of
    service condition or the disclosure of memory contents.
    (CVE-2016-4542)

  - A flaw exists in PHP in the exif_process_IFD_in_JPEG()
    function in exif.c due to improper validation of IFD
    sizes. An unauthenticated, remote attacker can exploit
    this, via crafted header data, to cause an out-of-bounds
    read error, resulting in a denial of service condition
    or the disclosure of memory contents. (CVE-2016-4543)

  - A man-in-the-middle vulnerability exists, known as
    'httpoxy', in the Apache Tomcat, Apache HTTP Server, and
    PHP components due to a failure to properly resolve
    namespace conflicts in accordance with RFC 3875 section
    4.1.18. The HTTP_PROXY environment variable is set based
    on untrusted user data in the 'Proxy' header of HTTP
    requests. The HTTP_PROXY environment variable is used by
    some web client libraries to specify a remote proxy
    server. A remote attacker can exploit this, via a
    crafted 'Proxy' header in an HTTP request, to redirect
    an application's internal HTTP traffic to an arbitrary
    proxy server where it may be observed or manipulated.
    (CVE-2016-5385, CVE-2016-5387, CVE-2016-5388)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05320149
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57f92332");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-32");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-587/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) version 7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

# Only Linux and Windows are affected -- HP-UX is not mentioned
os = get_kb_item_or_exit("Host/OS");
if ("Windows" >!< os && "Linux" >!< os) audit(AUDIT_OS_NOT, "Windows or Linux", os);

port = get_http_port(default:2381, embedded:TRUE);
app = "hp_smh";
get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['dir'];
version = install['version'];
prod = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");
source_line = get_kb_item("www/"+port+"/hp_smh/source");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, prod, build_url(port:port, qs:dir+"/") );

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  audit(AUDIT_VER_FORMAT, version);

if (ver_compare(ver:version_alt, fix:"7.6", strict:FALSE) == -1)
{
  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 7.6' +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xss:TRUE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
