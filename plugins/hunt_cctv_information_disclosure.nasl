#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64483);
  script_version ("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_cve_id("CVE-2013-1391");
  script_bugtraq_id(57579);
  script_osvdb_id(89737);
 
  script_name(english:"Hunt CCTV DVR.cfg Direct Request Information Disclosure");
  script_summary(english:"Tries to retrieve DVR.cfg");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is prone to an information disclosure attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server appears to be part of a digital video recorder
(DVR), such as models of Hunt CCTV, that is affected by an information
disclosure vulnerability.  Specifically, an unauthenticated remote
attacker can retrieve the device's configuration file, 'DVR.cfg', which
contains sensitive information, such as credentials in plaintext. This
information could facilitate other attacks.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jan/246");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_ATTACK); 
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english: "CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Hunt CCTV";

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (isnull(banner)) audit(AUDIT_WEB_BANNER_NOT, port);

if (
  'Basic realm="DVR"' >!< banner ||
   !egrep(pattern:"Server:.*httpd", string:banner)
) audit(AUDIT_NOT_DETECT, appname, port);

url = "/DVR.cfg";
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  "##########CAMERA##########" >< res[2] &&
  "#PTZ_PROTOCOL" >< res[2] &&
  "#CAMXX_PTZ_BAUDRATE" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    line_limit = 10;
    header = 
      'Nessus was able to exploit the issue to retrieve the contents of\n' +
      "'DVR.cfg' on the remote host:";
    trailer = '';
    
    if (report_verbosity > 1)
    {
      trailer = 
        'Here are its contents (limited to ' + line_limit + ' lines): \n' + 
        '\n' + 
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        beginning_of_response(resp:res[2], max_lines:line_limit) +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    }
    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
    security_note(port:port,extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:url));
