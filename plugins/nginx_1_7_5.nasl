#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78386);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/13 19:11:41 $");

  script_cve_id("CVE-2014-3616");
  script_bugtraq_id(70025);
  script_osvdb_id(111637);

  script_name(english:"nginx < 1.6.2 / 1.7.5 SSL Session Reuse");
  script_summary(english:"Checks the version of nginx.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an SSL session handling
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the server response header,
the version of nginx installed on the remote host is 0.5.6 or higher,
1.6.x prior to 1.6.2, or 1.7.x prior to 1.7.5. It is, therefore,
affected by an SSL session or TLS session ticket key handling error. A
flaw exists in the file 'event/ngx_event_openssl.c' that could allow a
remote attacker to obtain sensitive information or to take control of
a session.

Note that this issue only affects servers having multiple 'server{}'
configurations sharing the same values for 'ssl_session_cache' or
'ssl_session_ticket_key'.");
  # Researcher
  script_set_attribute(attribute:"see_also", value:"http://bh.ht.vc/vhost_confusion.pdf");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  # 1.6.2 announce
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000146.html");
  # 1.7.5 announce
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000145.html");
  # CVE-2014-3616 advisory
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000147.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.6");
  script_set_attribute(attribute:"solution", value:"Upgrade to nginx 1.6.2 / 1.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

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

server_header_tl = tolower(server_header);
if ("nginx" >!< server_header_tl) audit(AUDIT_WRONG_WEB_SERVER, port, "nginx");

vpieces = eregmatch(string: server_header_tl, pattern:"^nginx\/(.*)$");
if (isnull(vpieces)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "nginx", port);
version = vpieces[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^0(\.5)?$" || version =~ "^1(\.6)?$" || version =~ "^1(\.7)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "nginx", port, version);

# Affected : 0.5.6 - 1.7.4
# Fixed    : 1.6.2 , 1.7.5
if (
  # >= 0.5.6
  version =~ "^0\.5\.([6-9]([^0-9]|$)|[1-9]\d{1,})" ||
  version =~ "^0\.([6-9]([^0-9]|$)|[1-9]\d{1,})"    ||
  # 1.0.x - 1.5.x
  version =~ "^1\.[0-5]([^0-9]|$)"   ||
  # 1.6.x < 1.6.2
  version =~ "^1\.6\.[01]([^0-9]|$)" ||
  # 1.7.x < 1.7.5
  version =~ "^1\.7\.[0-4]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.6.2 / 1.7.5' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
