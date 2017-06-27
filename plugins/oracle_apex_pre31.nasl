# ---------------------------------------------------------------------------------
# (c) Recx Ltd 2009-2012
# http://www.recx.co.uk/
#
# Detection script for multiple issues within Oracle Application Express
#
# < 3.1
# 2 new security fixes for Oracle Application Express (formerly called HTML DB).
# 1 of these vulnerabilities may be remotely exploitable without authentication,
# i.e. may be exploited over a network without the need for a username and password
# http://www.oracle.com/technetwork/topics/security/cpuapr2008-082075.html
#
# Version 1.0
# ---------------------------------------------------------------------------------

include("compat.inc");

if (description)
{
  script_id(64716);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_name(english:"Oracle Application Express (Apex) Unspecified Issues (pre 3.1)");
  script_summary(english:"Checks if the Apex version is less than 3.1");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a vulnerable version of Oracle Apex." );
  script_set_attribute(
    attribute:"description",
    value:
"There are unspecified vulnerabilities in the Application Express
component of the Oracle Database. The updated version (3.1) contains
two security fixes for vulnerabilities of which one is remotely
exploitable without authentication."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade Application Express to at least version 3.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/developer-tools/apex/index.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2008-082075.html" );
  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/16");
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

if (version =~ "^[0-2]\." || version =~ "^3\.0(\.|$)")
{
  report = '\n  URL               : ' + url +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : 3.1' + '\n';
  raise_finding(port:port, report:report);
  exit(0);
}

exit(0, "The Oracle Apex install at " + url + " is version " + version + " and is not affected.");
