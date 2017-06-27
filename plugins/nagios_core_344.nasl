#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63563);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2012-6096");
  script_bugtraq_id(56879);
  script_osvdb_id(88322);
  script_xref(name:"EDB-ID", value:"24084");

  script_name(english:"Nagios Core history.cgi Multiple Parameter Buffer Overflow");
  script_summary(english:"Checks version of Nagios");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote web server hosts an application affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts a version of Nagios Core that is affected
by a buffer overflow vulnerability.  By sending a specially crafted
request using the 'host_name' or 'svc_description' parameter to
'history.cgi', a remote attacker may be able to execute arbitrary code
or trigger a denial of service condition."
  );
  script_set_attribute(attribute:"see_also", value:"http://pastebin.com/FJUNyTaj");
  script_set_attribute(attribute:"see_also", value:"http://www.nagios.org/projects/nagioscore/history/core-3x");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios Core 3.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios3 history.cgi Host Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("nagios_core_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

install = get_install_from_kb(appname:"nagios_core", port:port, exit_on_fail:TRUE);
dir = install['dir'];
version = install['ver'];
location = build_url(qs:dir + '/', port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Nagios Core", location);

item = eregmatch(pattern:"([0-9.]*[0-9])", string:version);
if (isnull(item[1]) || item[1] == "") exit(1, "Failed to parse the version string ('"+version+"').");

fix = "3.4.4";
if (ver_compare(ver:item[1], fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.4.4' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Nagios Core", location, version);
