#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64589);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2007-2897");
  script_bugtraq_id(51527);
  script_osvdb_id(41057);
  script_xref(name:"EDB-ID", value:"3965");

  script_name(english:"Microsoft ASP.NET MS-DOS Device Name DoS (PCI-DSS check)");
  script_summary(english:"Checks the web sever banner");

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
connects to a serial port. 

This plugin does not attempt to exploit the vulnerability and only runs
when 'Check for PCI-DSS compliance' is enabled in the scan policy.  This
plugin reports all web servers using ASP.NET 1.1.  If it cannot
determine the version, it will report all web servers using ASP.NET. 
Manual verification is required to determine if a vulnerability is
present."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/May/378");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/May/415");
  # https://groups.google.com/forum/?fromgroups=#!msg/microsoft.public.inetserver.iis/OUygrC7gO_A/Z0Juq-hkfZ0J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d32fbf50");
  script_set_attribute(
    attribute:"solution",
    value:
"Use an ISAPI filter to block requests for URLs with MS-DOS
device names."
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

  script_dependencies("webmirror.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

port = get_http_port(default:80, asp:TRUE);
banner = get_http_banner(port:port);

# check the banner first
if (!isnull(banner))
{
  headers = parse_http_headers(status_line:banner, headers:banner);
  poweredby = headers['x-powered-by'];
  aspnet_version = headers['x-aspnet-version'];

  if (
    aspnet_version =~ '^1\\.' ||
    (isnull(aspnet_version) && 'ASP.NET' >< poweredby)
  )
  {
    security_warning(port);
    exit(0);
  }
}

# then check each dir (the x-aspnet-version header appears to show up on a per-app basis)
foreach dir (cgi_dirs())
{
  url = dir + '/';
  if (url == '/') continue;  # already checked this

  res = http_send_recv3(method:'HEAD', item:url, port:port, exit_on_fail:TRUE);
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  aspnet_version = headers['x-aspnet-version'];

  if (aspnet_version =~ '^1\\.')
  {
    security_warning(port);
    exit(0);
  }
}

audit(AUDIT_LISTEN_NOT_VULN, 'web server', port);
