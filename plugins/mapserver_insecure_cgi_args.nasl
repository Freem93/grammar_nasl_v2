#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47861);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2010-2540");
  script_bugtraq_id(41855);
  script_osvdb_id(66838);

  script_name(english:"MapServer Insecure MapServ CGI Command-line Debug Args");
  script_summary(english:"Attempts to set MS_ERRORFILE to a non-existent file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI application that allows the use of
insecure command-line arguments.");

  script_set_attribute(attribute:"description", value:
"The version of MapServer installed on the remote host allows the use
of several insecure command-line debug arguments that are affected by
unspecified vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"http://trac.osgeo.org/mapserver/ticket/3485");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MapServer 5.6.4 / 4.6.10 or later if necessary and
reconfigure the application with MS_ENABLE_CGI_CL_DEBUG_ARGS
disabled.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("mapserver_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mapserver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'mapserver', port:port, exit_on_fail:TRUE);

nonexistentfile = '/nonexistentdir/'+unixtime()+'/'+SCRIPT_NAME;
url = install['dir']+'?MS_ERRORFILE%3d'+nonexistentfile;

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  'loadMap(): Web application error. CGI variable &quot;map&quot; is not set.' >< res[2] &&
  'msSetErrorFile(): General error message. Failed to open MS_ERRORFILE '+nonexistentfile >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      items:url,
      port:80
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The MapServer install at '+build_url(port:port, qs:install['dir'])+' is not affected because the insecure CGI args are disabled.');
