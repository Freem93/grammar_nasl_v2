#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79387);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_bugtraq_id(69683);
  script_osvdb_id(113383);

  script_name(english:"LiveZilla < 5.3.0.8 XSS");
  script_summary(english:"Checks the version of LiveZilla.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of LiveZilla hosted on the remote web server is affected
by an XSS vulnerability in the Mobile Client. This flaw is caused by
improper validation of user-supplied input. This vulnerability allows
an attacker to execute arbitrary code in the context of the victim's
browser.");
  script_set_attribute(attribute:"see_also", value:"http://forums.livezilla.net/index.php?/topic/163-livezilla-changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to LiveZilla version 5.3.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:livezilla:livezilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("livezilla_detect.nbin");
  script_require_keys("installed_sw/LiveZilla", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

appname = "LiveZilla";

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

path    = install["path"];
version = install["version"];
install_url = build_url(port:port, qs:path);

fix = '5.3.0.8';

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 5 ||
  (ver[0] == 5 && ver[1] < 3) ||
  (ver[0] == 5 && ver[1] == 3 && ver[2] == 0 && ver[3] < 8)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
