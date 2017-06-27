#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73122);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id("CVE-2012-3193", "CVE-2012-3194");
  script_bugtraq_id(55958, 56010);
  script_osvdb_id(86390, 86391, 91658);

  script_name(english:"Oracle Business Intelligence Publisher (October 2012 CPU)");
  script_summary(english:"Checks remote version.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Oracle Business Intelligence Publisher install is missing
the Oracle 2012 Critical Patch Update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the self-reported version of the Remote Oracle Business
Intelligence Publisher install, it is missing the October 2012 Critical
Patch Update.  It is, therefore, affected by multiple reflected
cross-site scripting vulnerabilities and an XML eXternal Entity (XXE)
injection vulnerability that could allow an authenticate user to gain
access to arbitrary files."
  );
  # https://web.archive.org/web/20130507120459/http://www.baesystemsdetica.com.au/Research/Advisories/Oracle-BI-Publisher-Multiple-Vulnerabilities-%28SS-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec0452db");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate Oracle Fusion Middleware October 2012 Critical
Patch Update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_bi_publisher_detect.nasl");
  script_require_keys("installed_sw/Oracle BI Publisher");
  script_require_ports("Services/www", 9704, 8888, 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = 'Oracle BI Publisher';
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:9704);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);

dir = install['path'];
install_url = build_url(port:port, qs:dir+"/login.jsp");

version = install['version'];
build = install['Build'];

report = '';

# note the space after '[02]', anchoring the regex
if (version =~ "^11\.1\.1\.6\.[02]([^0-9]|$)")
{
  if (build !~ "^[0-9.]+$") exit(0, "Unexpected build string format for the Oracle BI Publisher install at "+install_url+".");
  if (ver_compare(ver:build, fix:"20120927.1206", strict:FALSE) == -1)
  {
    report = '\n  Installed version : ' + version + ' build ' + build +
             '\n  Fixed version     : 11.1.1.6.4 build 20120927.1206' +
             '\n  Required patch    : 14630670\n';
  }
}
else if (version =~ "^11\.1\.1\.5\.0([^0-9]|$)")
{
  # 53(13879917) -> 53.13879917
  item = eregmatch(pattern:"^([0-9]+)(\(([0-9]+)\))?$", string:build);
  if (isnull(item)) exit(0, "Unexpected build string format for the Oracle BI Publisher install at "+install_url+".");
  build_check = item[1];
  if (!isnull(item[3])) build_check += "." + item[3];

  if (ver_compare(ver:build, fix:"53.13879917", strict:FALSE) == -1)
  {
    report = '\n  Installed version : ' + version + ' build ' + build +
             '\n  Fixed version     : 11.1.1.5.0 build 53(13879917)' +
             '\n  Required patch    : 14691557\n';
  }
}
else if (version =~ "^10\.1\.3\.4\.2([^0-9]|$)")
{
  if (build !~ "^[0-9]+$") exit(0, "Unexpected build string format for the Oracle BI Publisher install at "+install_url+".");
  if (int(build) < 1343)
  {
    report = '\n  Installed version : ' + version + ' build ' + build +
             '\n  Fixed version     : 10.1.3.4.2 build 1343' +
             '\n  Required patch    : 14625193\n';
  }
}

if (report != '')
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  URL               : ' + install_url + 
             report;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version + ' build ' + build);
