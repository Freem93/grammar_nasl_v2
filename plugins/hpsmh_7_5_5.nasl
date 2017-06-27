#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91222);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/14 14:40:46 $");

  script_cve_id(
    "CVE-2007-6750",
    "CVE-2011-4969",
    "CVE-2015-3194",
    "CVE-2015-3195",
    "CVE-2015-3237",
    "CVE-2015-7995",
    "CVE-2015-8035",
    "CVE-2016-0705",
    "CVE-2016-0799",
    "CVE-2016-2015",
    "CVE-2016-2842"
  );
  script_bugtraq_id(
    21865,
    58458,
    75387,
    77325,
    77390,
    78623,
    78626
  );
  script_osvdb_id(
    80056,
    121361,
    123400,
    126901,
    129696,
    131038,
    131039,
    135095,
    135096,
    135150,
    138397
  );
  script_xref(name:"HP", value:"emr_na-c05111017");
  script_xref(name:"HP", value:"HPSBMU03593");

  script_name(english:"HP System Management Homepage Multiple Vulnerabilities (HPSBMU03593)");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of HP System Management Homepage
(SMH) hosted on the remote web server is affected by the following
vulnerabilities :

  - A denial of service vulnerability exists in the Apache
    HTTP Server due to the lack of the mod_reqtimeout
    module. An unauthenticated, remote attacker can exploit
    this, via a saturation of partial HTTP requests, to
    cause a daemon outage. (CVE-2007-6750)

  - A cross-site scripting (XSS) vulnerability exists in
    jQuery when using location.hash to select elements. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted tag, to inject arbitrary script
    code or HTML into the user's browser session.
    (CVE-2011-4969)

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c due to improper handling of ASN.1 signatures
    that are missing the PSS parameter. A remote attacker
    can exploit this to cause the signature verification
    routine to crash, resulting in a denial of service
    condition. (CVE-2015-3194)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)

  - An out-of-bounds read error exists in cURL and libcurl
    within the smb_request_state() function due to improper
    bounds checking. An unauthenticated, remote attacker
    can exploit this, using a malicious SMB server and
    crafted length and offset values, to disclose sensitive
    memory information or to cause a denial of service
    condition. (CVE-2015-3237)

  - A flaw exists in libxslt in the xsltStylePreCompute()
    function within file preproc.c due to a failure to check
    if the parent node is an element. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted XML file, to cause a denial of service
    condition. (CVE-2015-7995)

  - An infinite loop condition exists in the xz_decomp()
    function within file xzlib.c when handling xz compressed
    XML content due to a failure to detect compression
    errors. An unauthenticated, remote attacker can exploit
    this, via specially crafted XML data, to cause a denial
    of service condition. (CVE-2015-8035)

  - A double-free error exists due to improper validation of
    user-supplied input when parsing malformed DSA private
    keys. A remote attacker can exploit this to corrupt
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-0705)

  - An out-of-bounds read error exists in the fmtstr()
    function within file crypto/bio/b_print.c when printing
    very long strings due to a failure to properly calculate
    string lengths. An unauthenticated, remote attacker can
    exploit this, via a long string, to cause a denial of
    service condition, as demonstrated by a large amount of
    ASN.1 data. (CVE-2016-0799)

  - An unspecified flaw exists that allows a local attacker
    to impact the confidentiality and integrity of the
    system. No other details are available. (CVE-2016-2015)

  - A flaw exists in the doapr_outch() function within file
    crypto/bio/b_print.c due to a failure to verify that a
    certain memory allocation succeeds. An unauthenticated,
    remote attacker can exploit this, via a long string,
    to cause a denial of service condition, as demonstrated
    by a large amount of ASN.1 data. (CVE-2016-2842)");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05111017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fea15d14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage version 7.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, prod, build_url(port:port, qs:dir+"/") );

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  audit(AUDIT_VER_FORMAT, version);

if (
    ver_compare(ver:version_alt, fix:"7.5.5", strict:FALSE) == -1
   )
{
  source_line = get_kb_item("www/"+port+"/hp_smh/source");
  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;

  report_items = make_array(
    "Installed version", version,
    "Fixed version", "7.5.5"
  );
  order = make_list("Installed version", "Fixed version");
  report += report_items_str(report_items:report_items, ordered_fields:order);
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xss:TRUE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
