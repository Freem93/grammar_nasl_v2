#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64588);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2007-2897");
  script_bugtraq_id(51527);
  script_osvdb_id(41057);
  script_xref(name:"EDB-ID", value:"3965");

  script_name(english:"Microsoft ASP.NET MS-DOS Device Name DoS");
  script_summary(english:"Attempts a PoC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A framework used by the remote web server has a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web server running on the remote host appears to be using Microsoft
ASP.NET, and may be affected by a denial of service vulnerability. 
Requesting a URL containing an MS-DOS device name can cause the web
server to become temporarily unresponsive.  An attacker could repeatedly
request these URLs, resulting in a denial of service. 

Additionally, there is speculation that this vulnerability could result
in code execution if an attacker with physical access to the machine
connects to a serial port."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/May/378");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/May/415");
  # https://groups.google.com/forum/?fromgroups=#!msg/microsoft.public.inetserver.iis/OUygrC7gO_A/Z0Juq-hkfZ0J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d32fbf50");
  script_set_attribute(
    attribute:"solution",
    value:
"Use an ISAPI filter to block requests for URLs with MS-DOS device
names."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (!get_kb_item('Settings/ParanoidReport')) audit(AUDIT_PARANOID);

port = get_http_port(default:80, asp:TRUE);

url = '/AUX/.aspx';
timeout = get_read_timeout() + 10;
http_set_read_timeout(timeout);
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
headers = parse_http_headers(status_line:res[0], headers:res[1]);

if (
  headers['$code'] == 500 ||
  'Runtime Error' >< res[2] ||
  'HttpException' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header =
      'Nessus received an HTTP 500 or related error message by requesting\n' +
      'the following URL';
    report = get_vuln_report(header:header, items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'web server', port);
