#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78090);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id(
    "CVE-2013-4545",
    "CVE-2013-6420",
    "CVE-2013-6422",
    "CVE-2013-6712",
    "CVE-2014-2640",
    "CVE-2014-2641",
    "CVE-2014-2642"
  );
  script_bugtraq_id(63776, 64018, 64225, 64431, 70206, 70208);
  script_osvdb_id(99972, 100440, 100979, 101177, 112410, 112411, 112412);
  script_xref(name:"HP", value:"emr_na-c04463322");
  script_xref(name:"CERT", value:"125228");

  script_name(english:"HP System Management Homepage < 7.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the banner.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is affected
by the following vulnerabilities :

  - A flaw exists within the included cURL that disables the
    'CURLOPT_SSLVERIFYHOST' check when the setting on
    'CURLOPT_SSL_VERIFYPEER' is disabled. This can allow a
    remote attacker to disable SSL certificate host name
    checks. (CVE-2013-4545)

  - A flaw exists in the included PHP 'openssl_x509_parse'
    function due to user input not being properly sanitized.
    Using a specially crafted certificate, a remote attacker
    can exploit this to cause a denial of service or execute
    arbitrary code. (CVE-2013-6420)

  - A flaw exists within the included cURL where the
    verification check for the CN and SAN name fields is
    skipped due to the digital signature verification being
    disabled. A remote attacker can exploit this to spoof
    servers or conduct a man-in-the-middle attack.
    (CVE-2013-6422)

  - A flaw exists in the scan function within the included
    PHP 'ext/date/lib/parse_iso_intervals.c' script where
    user input is not properly sanitized. This can allow a
    remote attacker to cause a denial of service using a
    heap-based buffer overflow. (CVE-2013-6712)

  - An unspecified cross-site scripting flaw exists which
    can allow a remote attacker, using a specially crafted
    request, to execute arbitrary code within the
    browser / server trust relationship. (CVE-2014-2640)

  - An unspecified cross-site request forgery vulnerability
    exists. (CVE-2014-2641)

  - An unspecified vulnerability exists that can allow
    a remote attacker to conduct clickjacking attacks.
    (CVE-2014-2642)");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04463322
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0858b492");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533589/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/08");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

port    = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# Only Linux and Windows are affected -- HP-UX is not mentioned
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os && "Linux" >!< os) audit(AUDIT_OS_NOT, "Windows or Linux", os);
}

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt)) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.4';
if (
  version_alt =~ "^7\.[34]([^0-9]|$)" &&
  ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  source_line = get_kb_item("www/"+port+"/hp_smh/source");

  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + 
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xss:TRUE, xsrf:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
