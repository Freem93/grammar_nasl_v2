# ---------------------------------------------------------------------------------
# (c) Recx Ltd 2009-2012
# http://www.recx.co.uk/
#
# Detection script for multiple issues within Oracle Application Express
#
# < 2.2.1
# 35 new security fixes for Oracle Application Express, 25 of which may be remotely exploitable without authentication.
# The Oracle Application Express security vulnerabilities listed in the risk matrix above are fixed in version 2.2.1. All previous versions should be upgraded directly to version 2.2.1
# http://www.oracle.com/technetwork/topics/security/cpuoct2006-095368.html
#
# Version 1.0
# ---------------------------------------------------------------------------------

include("compat.inc");

if (description)
{
  script_id(64714);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2006-5351", "CVE-2006-5352");
  script_bugtraq_id(20588);
  script_osvdb_id(
    31469,
    31470,
    31471,
    31472,
    31473,
    31474,
    31475,
    31476,
    31477,
    31478,
    31479,
    31480,
    31481,
    31482,
    31483,
    31484,
    31485,
    31486,
    31487,
    31488,
    31489,
    31490,
    31491,
    31492,
    31493,
    31494,
    31495,
    31496,
    31497,
    31498,
    31499,
    31500,
    31501,
    31502,
    31503
  );

  script_name(english:"Oracle Application Express (Apex) Unspecified Issues (pre 2.2.1)");
  script_summary(english:"Checks whether the Apex version is less than 2.2.1");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a vulnerable version of Oracle Apex." );
  script_set_attribute(
    attribute:"description",
    value:
"There are unspecified vulnerabilities in versions prior to version
2.2.1 of the Oracle Application Express component of the Oracle
Database. The updated version of Apex contains '35 new security fixes
for Oracle Application Express, 25 of which may be remotely
exploitable without authentication'."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade Application Express to at least version 2.2.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-486");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/developer-tools/apex/index.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2006-095368.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:application_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Recx Ltd.");

  script_dependencies("oracle_apex_detect_version.nasl");
  script_require_keys("Oracle/Apex");
  script_require_ports("Services/www", 8080, 80, 443);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

function raise_finding(port, report)
{
  if(report_verbosity > 0)
    security_hole(port:port, extra:report);
  else security_hole(port);
}

port = get_http_port(default:8080);

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

version = get_kb_item("Oracle/Apex/"+port+"/Version");
if(!version) exit(0, "The 'Oracle/Apex/" + port + "/Version' KB item is not set.");

location = get_kb_item("Oracle/Apex/" + port + "/Location");
if(!location) exit(0, "The 'Oracle/Apex/" + port + "/Location' KB item is not set.");
url = build_url(qs:location, port:port);

if (version =~ "^[0-1]\." || version =~ "^2\.[0-1](\.|$)" ||
    version == "2.2")
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  report = '\n  URL               : ' + url +
   	   '\n  Installed version : ' + version +
           '\n  Fixed version     : 2.2.1' + '\n';
  raise_finding(port:port, report:report);
  exit(0);
}

exit(0, "The Oracle Apex install at " + url + " is version " + version + " and is not affected.");
