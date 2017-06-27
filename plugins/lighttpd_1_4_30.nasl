#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57410);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/21 19:27:16 $");

  script_cve_id("CVE-2011-4362");
  script_bugtraq_id(50851);
  script_osvdb_id(77366);
  script_xref(name:"EDB-ID", value:"18295");

  script_name(english:"lighttpd < 1.4.30 base64_decode Function Out-of-Bounds Read Error DoS");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.30. It is, therefore, affected by a denial of
service vulnerability. The HTTP server allows out-of-bounds values to
be decoded during the auth process and later uses these values as
offsets. Using negative values as offsets can result in application
crashes.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fc05344");
  script_set_attribute(attribute:"see_also", value:"http://redmine.lighttpd.net/issues/2370");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2011_01.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.30 or later. Alternatively, apply the
vendor-supplied patch or disable mod_auth.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0, "The web server listening on port " + port + " does not send a Server response header.");

if ("lighttpd" >!< tolower(server_header))
  exit(0, "The web server listening on port " + port + " is not lighttpd.");

matches = eregmatch(string:server_header, pattern:"^lighttpd\/([a-zA-Z0-9.-_]+)");
if (!matches) exit(1, "Failed to extract the version of the lighttpd server listening on port "+port+".");
version = matches[1];

if (version =~ "^1\.([0-3]\.|4\.([0-9]|[012][0-9])([^0-9]|$))")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.30\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The lighttpd "+version+" installed listening on the port "+port+" is not affected.");
