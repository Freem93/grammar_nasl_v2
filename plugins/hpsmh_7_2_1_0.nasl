#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69020);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2012-0883",
    "CVE-2012-2110",
    "CVE-2012-2311",
    "CVE-2012-2329",
    "CVE-2012-2335",
    "CVE-2012-2336",
    "CVE-2012-5217",
    "CVE-2013-2355",
    "CVE-2013-2356",
    "CVE-2013-2357",
    "CVE-2013-2358",
    "CVE-2013-2359",
    "CVE-2013-2360",
    "CVE-2013-2361",
    "CVE-2013-2362",
    "CVE-2013-2363",
    "CVE-2013-2364",
    "CVE-2013-4821"
  );
  script_bugtraq_id(
    49778,
    53046,
    53158,
    53388,
    53455,
    61332,
    61333,
    61335,
    61336,
    61337,
    61338,
    61339,
    61340,
    61341,
    61342,
    61343,
    62622
  );
  script_osvdb_id(
    74829,
    81223,
    81359,
    81633,
    82213,
    82215,
    95481,
    95482,
    95483,
    95484,
    95485,
    95486,
    95487,
    95488,
    95489,
    95490,
    95491,
    97547
  );
  script_xref(name:"CERT", value:"895524");
  script_xref(name:"HP", value:"HPSBMU02900");
  script_xref(name:"HP", value:"SSRT100740");
  script_xref(name:"HP", value:"SSRT101209");
  script_xref(name:"HP", value:"SSRT101210");
  script_xref(name:"HP", value:"SSRT100992");
  script_xref(name:"HP", value:"SSRT100992");
  script_xref(name:"HP", value:"SSRT100992");
  script_xref(name:"HP", value:"SSRT100992");
  script_xref(name:"HP", value:"SSRT101137");
  script_xref(name:"HP", value:"SSRT100696");
  script_xref(name:"HP", value:"SSRT100835");
  script_xref(name:"HP", value:"SSRT100907");
  script_xref(name:"HP", value:"SSRT100907");
  script_xref(name:"HP", value:"SSRT100907");
  script_xref(name:"HP", value:"SSRT100907");
  script_xref(name:"HP", value:"SSRT101007");
  script_xref(name:"HP", value:"SSRT101076");
  script_xref(name:"HP", value:"SSRT101150");
  script_xref(name:"HP", value:"SSRT101151");
  script_xref(name:"HP", value:"SSRT101254");
  script_xref(name:"HP", value:"emr_na-c03839862");

  script_name(english:"HP System Management Homepage < 7.2.1.0 Multiple Vulnerabilities (BEAST)");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is a version
prior to 7.2.1.0. It is, therefore, affected by the following
vulnerabilities :

  - An information disclosure vulnerability, known as BEAST,
    exists in the SSL 3.0 and TLS 1.0 protocols due to a
    flaw in the way the initialization vector (IV) is
    selected when operating in cipher-block chaining (CBC)
    modes. A man-in-the-middle attacker can exploit this
    to obtain plaintext HTTP header data, by using a
    blockwise chosen-boundary attack (BCBA) on an HTTPS
    session, in conjunction with JavaScript code that uses
    the HTML5 WebSocket API, the Java URLConnection API,
    or the Silverlight WebClient API. (CVE-2011-3389)

  - The utility 'apachectl' can receive a zero-length
    directory name in the LD_LIBRARY_PATH via the 'envvars'
    file. A local attacker with access to that utility
    could exploit this to load a malicious Dynamic Shared
    Object (DSO), leading to arbitrary code execution.
    (CVE-2012-0883)

  - Numerous, unspecified errors could allow remote denial
    of service attacks. (CVE-2012-2110, CVE-2012-2329,
    CVE-2012-2336, CVE-2013-2357, CVE-2013-2358,
    CVE-2013-2359, CVE-2013-2360)

  - The fix for CVE-2012-1823 does not completely correct
    the CGI query parameter vulnerability. Disclosure of
    PHP source code and code execution are still possible.
    Note that this vulnerability is exploitable only when
    PHP is used in CGI-based configurations.  Apache with
    'mod_php' is not an exploitable configuration.
    (CVE-2012-2311, CVE-2012-2335)

  - Unspecified errors exist that could allow unauthorized
    access. (CVE-2012-5217, CVE-2013-2355)

  - Unspecified errors exist that could allow disclosure of
    sensitive information. (CVE-2013-2356, CVE-2013-2363)

  - An unspecified error exists that could allow cross-site
    scripting attacks. (CVE-2013-2361)

  - Unspecified errors exist that could allow a local
    attacker to cause denial of service conditions.
    (CVE-2013-2362, CVE-2013-2364)

  - An as-yet unspecified vulnerability exists that could 
    cause a denial of service condition. (CVE-2013-4821)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-204/");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03839862-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd41e44");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528723/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 7.2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP apache_request_headers Function Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER)
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.2.1.0';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
