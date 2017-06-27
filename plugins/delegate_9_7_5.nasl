#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27582);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/25 23:45:39 $");

  script_bugtraq_id(26174);
  script_osvdb_id(41862, 41863, 41864, 41865, 41866);

  script_name(english:"DeleGate Proxy Server < 9.7.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of DeleGate Proxy server");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of the
DeleGate proxy server before 9.7.5. Such versions contain several
issues that could result in service disruptions when processing user
input or handling malicious traffic.");
  script_set_attribute(attribute:"see_also", value:"http://www.delegate.org/mail-lists/delegate-en/3829");
  script_set_attribute(attribute:"see_also", value:"http://www.delegate.org/mail-lists/delegate-en/3856");
  script_set_attribute(attribute:"see_also", value:"http://www.delegate.org/mail-lists/delegate-en/3875");
  script_set_attribute(attribute:"solution", value:"Upgrade to DeleGate 9.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("proxy_use.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 8080, 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/http_proxy");
if (!port) port = 8080;
if (!get_port_state(port)) exit(0);

banner = get_http_banner(port:port);

if (banner && "DeleGate-Ver: " >< banner)
{
  headers = banner - strstr(banner, '\n\n');
  ver = strstr(headers, "DeleGate-Ver: ") - "DeleGate-Ver: ";
  if (ver) ver = ver - strstr(ver, '\n');
  if (ver && " (delay=" >< ver ) ver = ver - strstr(ver, " (delay=");

  # Versions < 9.7.5 are vulnerable
  if (ver =~ "^([0-8]\..*)|(9\.(([0-6]\..*)|7\.[0-4][^0-9]))")
  {
      extra = 'According to its banner, the remote proxy is DeleGate version '+ ver + '.\n';
      security_warning(port:port,extra:extra);
  }
}
