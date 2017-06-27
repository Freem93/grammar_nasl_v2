#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53209);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2011-1524", "CVE-2011-0545");
  script_bugtraq_id(46856);
  script_osvdb_id(71261, 73143);
  script_xref(name:"EDB-ID", value:"17026");

  script_name(english:"Symantec LiveUpdate Administrator < 2.3 CSRF (SYM11-005)");
  script_summary(english:"Checks LUA version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site request forgery
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of LiveUpdate Administrator running on the remote host is
earlier than 2.3.  Such versions have a cross-site request forgery
(CSRF) vulnerability.  Failed login attempts are logged and viewable
from the web console. Usernames from these failed attempts are not
sanitized before they are displayed in the log, which could result
in a cross-site request forgery attack.

A remote attacker could exploit this by attempting to login with a
maliciously crafted username, resulting in arbitrary script execution
the next time an admin user views the Event Log."
  );
  script_set_attribute(attribute:"see_also", value:"http://sotiriu.de/adv/NSOADV-2011-001.txt");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b35b9aa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to LiveUpdate Administrator 2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:liveupdate_administrator");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_lua_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/symantec_lua");
  script_require_ports("Services/www", 7070, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:7070);
install = get_install_from_kb(appname:'symantec_lua', port:port, exit_on_fail:TRUE);

dir = install['dir'];
ver = install['ver'];
if (ver == UNKNOWN_VER) exit(1, 'Unknown LUA version on port '+port+'.');

fix = '2.3';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) != -1)
  exit(0, 'Version '+ver+' on port '+port+' is not affected.');

if (report_verbosity > 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  report =
    '\n  URL               : ' + build_url(qs:dir, port:port) +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
