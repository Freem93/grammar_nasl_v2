#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97893);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/24 14:02:38 $");

  script_cve_id(
    "CVE-2015-8861",
    "CVE-2015-8862",
    "CVE-2016-1283",
    "CVE-2016-1833",
    "CVE-2016-1834",
    "CVE-2016-1835",
    "CVE-2016-1836",
    "CVE-2016-1837",
    "CVE-2016-1838",
    "CVE-2016-1839",
    "CVE-2016-1840",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2107",
    "CVE-2016-2108",
    "CVE-2016-2109",
    "CVE-2016-2176",
    "CVE-2016-3191",
    "CVE-2016-3627",
    "CVE-2016-3705",
    "CVE-2016-4447",
    "CVE-2016-4448",
    "CVE-2016-4449",
    "CVE-2016-4483",
    "CVE-2016-5419",
    "CVE-2016-5420",
    "CVE-2016-5421",
    "CVE-2016-9261"
  );
  script_bugtraq_id(
    79825,
    84810,
    84992,
    87940,
    89744,
    89746,
    89752,
    89757,
    89760,
    89854,
    90013,
    90856,
    90864,
    90865,
    92292,
    92306,
    92309,
    96434,
    96436
  );
  script_osvdb_id(
    130651,
    130653,
    131671,
    132469,
    132727,
    132973,
    133765,
    134395,
    134833,
    135475,
    136194,
    137577,
    137896,
    137897,
    137898,
    137899,
    137900,
    137962,
    137965,
    138566,
    138567,
    138568,
    138569,
    138572,
    138921,
    138926,
    138927,
    138928,
    138966,
    142492,
    142493,
    142494,
    147026,
    151706
  );
  script_xref(name:"EDB-ID", value:"39491");
  script_xref(name:"EDB-ID", value:"39492");
  script_xref(name:"EDB-ID", value:"39493");
  script_xref(name:"EDB-ID", value:"39494");
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Tenable Log Correlation Engine (LCE) < 4.8.1 Multiple Vulnerabilities");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"A data aggregation application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Tenable Log Correlation Engine (LCE) installed on the
remote host is prior to 4.8.1. It is, therefore, affected by the
following vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the Handlebars library in the
    lib/handlebars/utils.js script due to a failure to
    properly escape input passed as unquoted attributes to
    templates. An unauthenticated, remote attacker can
    exploit these vulnerabilities, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2015-8861, CVE-2015-8862)

  - A heap-based buffer overflow condition exists in the
    Perl-Compatible Regular Expressions (PCRE) component
    that is triggered when processing nested back references
    in a duplicate named group. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1283)

  - An out-of-bounds read error exists in the libxml2
    component in parserInternals.c due to improper parsing
    of characters in an XML file. An unauthenticated, remote
    attacker can exploit this to disclose sensitive
    information or cause a denial of service condition.
    (CVE-2016-1833)

  - An overflow condition exists in the libxml2 component in
    xmlstring.c due to improper validation of user-supplied
    input when handling a string with NULL. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1834)

  - Multiple use-after-free errors exist in the libxml2
    component in parser.c that is triggered when parsing
    complex names. An unauthenticated, remote attacker can
    exploit these issues, via a specially crafted file, to
    dereference already freed memory and potentially execute
    arbitrary code. (CVE-2016-1835, CVE-2016-1836)

  - Multiple heap-based buffer overflow conditions exist in
    the libxml2 component in HTMLparser.c and xmlregexp.c
    due to improper validation of user-supplied input when
    parsing characters in a range. An unauthenticated,
    remote attacker can exploit these issues, via a
    specially crafted file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1837, CVE-2016-1839, CVE-2016-1840)

  - Multiple out-of-bounds read errors exist in the libxml2
    component in parser.c. An unauthenticated, remote
    attacker can exploit these issues to disclose sensitive
    information or cause a denial of service condition.
    (CVE-2016-1838, CVE-2016-4447)

  - A heap buffer overflow condition exists in the OpenSSL
    component in the EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling a
    large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in the OpenSSL
    component in the EVP_EncryptUpdate() function within
    file crypto/evp/evp_enc.c that is triggered when
    handling a large amount of input data after a previous
    call occurs to the same function with a partial block.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - Flaws exist in the aesni_cbc_hmac_sha1_cipher()
    function in file crypto/evp/e_aes_cbc_hmac_sha1.c and
    the aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - A remote code execution vulnerability exists in the
    OpenSSL component in the ASN.1 encoder due to an
    underflow condition that occurs when attempting to
    encode the value zero represented as a negative integer.
    An unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code. (CVE-2016-2108)

  - Multiple unspecified flaws exist in the d2i BIO
    functions when reading ASN.1 data from a BIO due to
    invalid encoding causing a large allocation of memory.
    An unauthenticated, remote attacker can exploit these to
    cause a denial of service condition through resource
    exhaustion. (CVE-2016-2109)

  - An out-of-bounds read error exists in the
    X509_NAME_oneline() function within file
    crypto/x509/x509_obj.c when handling very long ASN1
    strings. An unauthenticated, remote attacker can exploit
    this to disclose the contents of stack memory.
    (CVE-2016-2176)

  - An overflow condition exists in the Perl-Compatible
    Regular Expressions (PCRE) component due to improper
    validation of user-supplied input when handling the
    (*ACCEPT) verb. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2016-3191)

  - A flaw exists in the libxml2 component in parser.c that
    occurs when handling XML content in recovery mode. An
    unauthenticated, remote attacker can exploit this to
    cause a stack exhaustion, resulting in a denial of
    service condition. (CVE-2016-3627)

  - A flaw exists in the libxml2 component in parser.c due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a stack exhaustion, resulting in a denial of
    service condition. (CVE-2016-3705)

  - A format string flaw exists in the libxml2 component due
    to improper use of string format specifiers (e.g. %s and
    %x). An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-4448)

  - An XML external entity injection vulnerability exists in
    parser.c due to improper parsing of XML data. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted XML data, to disclose arbitrary files
    or cause a denial of service condition. (CVE-2016-4449)

  - An out-of-bounds read error exists in the libxml2
    component in xmlsave.c that occurs when handling XML
    content in recovery mode. An unauthenticated, remote
    attacker can exploit this to disclose sensitive
    information or cause a denial of service condition.
    (CVE-2016-4483)

  - A security bypass vulnerability exists in the libcurl
    component due to the program attempting to resume TLS
    sessions even if the client certificate fails. An
    unauthenticated, remote attacker can exploit this to
    bypass validation mechanisms. (CVE-2016-5419)

  - An information disclosure vulnerability exists in the
    libcurl component due to the program reusing TLS
    connections with different client certificates. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive cross-realm information.
    (CVE-2016-5420)

  - A use-after-free error exists in the libcurl component
    that is triggered as connection pointers are not
    properly cleared for easy handles. An unauthenticated,
    remote attacker can exploit this to dereference already
    freed memory, potentially resulting in the execution of
    arbitrary code. (CVE-2016-5421)

  - Multiple stored cross-site scripting (XSS)
  	vulnerabilities exist due to improper validation of
  	user-supplied input. An authenticated, remote attacker
  	can exploit these, via a specially crafted request, to
  	execute arbitrary script code in a user's browsers
  	session. (CVE-2016-9261, VulnDB 151706)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-18");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable LCE version 4.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:log_correlation_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("lce_installed.nbin");
  script_require_keys("installed_sw/Log Correlation Engine Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "Log Correlation Engine Server";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = '4.8.1';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    xss:TRUE,
    extra:
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
