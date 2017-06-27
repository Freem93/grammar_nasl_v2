#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49659);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_bugtraq_id(43333);
  script_osvdb_id(68133, 68134, 68135);
  script_xref(name:"Secunia", value:"41520");

  script_name(english:"Syncrify < 2.1 Build 420 Multiple Security Bypass Vulnerabilities");
  script_summary(english:"Checks the Syncrify Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple security bypass vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version, the remote installation of Syncrify is
affected by multiple security bypass vulnerabilities :

  - The application fails to restrict access to the password
    management page and allows users to change the
    administrator's password by directly accessing that
    page.

  - It is possible for users to browse and download
    unauthorized files by accessing them directly.");

  script_set_attribute(attribute:"see_also", value:"http://web.synametrics.com/SyncrifyVersionHistory.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to Syncrify 2.1 build 420, or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("syncrify_web_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 5800);
  script_require_keys("www/syncrify");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:5800);

install = get_install_from_kb(appname:'syncrify', port:port, exit_on_fail:TRUE);

dir =     install['dir'];
version = install['ver'];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) exit(1, "It was not possible to determine the version of Syncrify installed at "+install_url+".");

if (
  version =~ '^([01]\\.[0-9]+|2\\.0)' ||                                  # version number is less than 2.1
  version =~ '^2\\.1 - build ([0-9]{1,2}|[0-3][0-9]{2}|4([01][0-9]))($|[^0-9])' # version number is 2.1 but build # is less than 420
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.1 Build 420' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'Syncrify '+version+' is installed at '+install_url+' and thus not affected.');
