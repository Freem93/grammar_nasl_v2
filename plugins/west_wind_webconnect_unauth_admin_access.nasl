#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62202);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_osvdb_id(83043);

  script_name(english:"West Wind Web Connection Unprotected Configuration Editor Application");
  script_summary(english:"Checks for unprotected administration application");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running an unprotected web administration
application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a web application that utilizes the West
Wind Web Connection framework.  Nessus was able to access the West Wind
Web Connection framework configuration file editor without providing
credentials.  The configuration file editor allows remote configuration
of the application and the underlying framework, which may allow
attackers to execute arbitrary applications on the remote host.

Additionally, it is likely that there are other unprotected
administration applications."
  );
  script_set_attribute(attribute:"solution", value:"Contact the application vendor for a solution or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:west_wind:web_connection");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
dirs = list_uniq(make_list('', '/wconnect', cgi_dirs()));
installs = NULL;

foreach dir (dirs)
{
  url = dir + '/wc.dll?wwMaint~EditConfig';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

  if (
    '<title>Editing Config Files</title>' >< res[2] &&
    'West Wind Technologies' >< res[2] &&
    'INI Settings' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      header = 'Nessus was able to access the INI file editor at the following url';

      report = get_vuln_report(items:url, header:header, port:port);
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}

exit(0, 'No vulnerable installs were detected on port ' + port);
