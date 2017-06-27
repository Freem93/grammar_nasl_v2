#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76311);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/03 10:38:32 $");

  script_cve_id("CVE-2014-3913");
  script_bugtraq_id(67777);
  script_osvdb_id(107674);

  script_name(english:"Ericom AccessNow Server < 3.3.1.4095 Stack-Based Buffer Overflow");
  script_summary(english:"Checks AccessNow Server version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server has an Ericom AccessNow server product prior to
version 3.3.1.4095. It is, therefore, affected by a stack-based buffer
overflow vulnerability that can be triggered by requesting a
non-existent file. Successful exploitation can result in remote code
execution or a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.ericom.com/security-ERM-2014-610.asp");
  script_set_attribute(attribute:"solution", value:"Upgrade to AccessNow version 3.3.1.4095 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ericom AccessNow Server Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ericom:accessnow_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ericom_accessnow_detect.nbin");
  script_require_keys("www/ericomaccessnow");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

appname = "Ericom AccessNow";

install = get_install_from_kb(
  appname      : 'ericomaccessnow',
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];

install_loc = build_url(port:port, qs:dir + "/");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_loc);

fixed = '3.3.1.4095';

if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' + fixed + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname,  install_loc, version);
