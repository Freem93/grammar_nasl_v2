#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73519);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/12 18:55:23 $");

  script_cve_id("CVE-2014-0133");
  script_bugtraq_id(66537);
  script_osvdb_id(104711);

  script_name(english:"nginx < 1.4.7 / 1.5.12 SPDY Heap Buffer Overflow");
  script_summary(english:"Checks version of nginx");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a heap buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the server response header,
the installed 1.3.x version of nginx is 1.3.15 or higher, or 1.4.x
prior to 1.4.7, or 1.5.x prior to 1.5.12. It is, therefore, affected
by a heap buffer overflow vulnerability.

A flaw exists with the SPDY protocol implementation where user input
is not properly validated. This could allow a remote attacker to cause
a heap-based buffer overflow, causing a denial of service or potential
arbitrary code execution.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000135.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/download/patch.2014.spdy2.txt");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.4");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"solution", value:"Apply the patch manually or upgrade to nginx 1.4.7 / 1.5.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/nginx");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/nginx");

port = get_http_port(default:80);

server_header = http_server_header(port:port);
if (isnull(server_header)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

if ("nginx" >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, "nginx");

vpieces = eregmatch(string: server_header, pattern:"^nginx\/(.*)$");
if (isnull(vpieces)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "nginx", port);
version = vpieces[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^1(\.3)?$" || version =~ "^1(\.4)?$" || version =~ "^1(\.5)?$")  audit(AUDIT_VER_NOT_GRANULAR, "nginx", port, version);

# Affected: 1.3.15 - 1.4.7, 1.5.0 - 1.5.12
if (
  version =~ "^1\.3\.(1[5-9]|[2-9][0-9])([^0-9]|$)" ||
  version =~ "^1\.4\.[0-6]([^0-9]|$)" ||
  version =~ "^1\.5\.([0-9]|1[01])([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.7 / 1.5.12' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
