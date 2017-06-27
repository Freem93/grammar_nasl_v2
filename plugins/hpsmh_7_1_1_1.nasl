#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59851);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id(
    "CVE-2011-1944",
    "CVE-2011-2821",
    "CVE-2011-2834",
    "CVE-2011-3379",
    "CVE-2011-3607",
    "CVE-2011-4078",
    "CVE-2011-4108",
    "CVE-2011-4153",
    "CVE-2011-4317",
    "CVE-2011-4415",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4619",
    "CVE-2011-4885",
    "CVE-2012-0021",
    "CVE-2012-0027",
    "CVE-2012-0031",
    "CVE-2012-0036",
    "CVE-2012-0053",
    "CVE-2012-0057",
    "CVE-2012-0830",
    "CVE-2012-1165",
    "CVE-2012-1823",
    "CVE-2012-2012",
    "CVE-2012-2013",
    "CVE-2012-2014",
    "CVE-2012-2015",
    "CVE-2012-2016"
  );
  script_bugtraq_id(
    48056,
    49754,
    50402,
    50494,
    50639,
    50802,
    51193,
    51281,
    51407,
    51417,
    51665,
    51705,
    51706,
    51806,
    51830,
    52764,
    53388,
    54218
  );
  script_osvdb_id(
    73248,
    74695,
    75560,
    75713,
    76744,
    77012,
    77047,
    77310,
    78115,
    78186,
    78188,
    78189,
    78190,
    78191,
    78293,
    78512,
    78555,
    78556,
    78570,
    78676,
    78819,
    80040,
    81633,
    83258,
    83259,
    83260,
    83332,
    83333
  );

  script_name(english:"HP System Management Homepage < 7.1.1 Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote host is earlier than
7.1.1 and is, therefore, reportedly affected by the following
vulnerabilities :

  - The bundled version of the libxml2 library contains
    multiple vulnerabilities. (CVE-2011-1944, CVE-2011-2821,
    CVE-2011-2834)

  - The bundled version of PHP contains multiple
    vulnerabilities. (CVE-2011-3379, CVE-2011-4153, 
    CVE-2011-4885, CVE-2012-1823, CVE-2012-0057, 
    CVE-2012-0830)

  - The bundled version of the Apache HTTP Server contains
    multiple vulnerabilities. (CVE-2011-3607, CVE-2011-4317,
    CVE-2011-4415, CVE-2012-0021, CVE-2012-0031, 
    CVE-2012-0053)

  - An issue exists in the 'include/iniset.php' script in
    the embedded RoundCube Webmail version that could lead
    to a denial of service. (CVE-2011-4078)

  - The bundled version of OpenSSL contains multiple 
    vulnerabilities. (CVE-2011-4108, CVE-2011-4576,
    CVE-2011-4577, CVE-2011-4619, CVE-2012-0027,
    CVE-2012-1165)

  - The bundled version of curl and libcurl does not 
    properly consider special characters during extraction
    of a pathname from a URL. (CVE-2012-0036)
    
  - An off autocomplete attribute does not exist for 
    unspecified form fields, which makes it easier for 
    remote attackers to obtain access by leveraging an
    unattended workstation. (CVE-2012-2012)

  - An unspecified vulnerability exists that could allow a
    remote attacker to cause a denial of service, or
    possibly obtain sensitive information or modify data.
    (CVE-2012-2013)

  - An unspecified vulnerability exists related to improper
    input validation. (CVE-2012-2014)

  - An unspecified vulnerability allows remote, 
    unauthenticated users to gain privileges and obtain 
    sensitive information. (CVE-2012-2015)

  - An unspecified vulnerability allows local users to
    obtain sensitive information via unknown vectors.
    (CVE-2012-2016)"
  );
   # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03360041
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?541c7466"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/523320/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to HP System Management Homepage 7.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/05");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("global_settings.inc");
include("audit.inc");
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

fixed_version = '7.1.1.1';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
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
