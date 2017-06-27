#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86884);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_osvdb_id(129558);

  script_name(english:"nginx 1.9.x < 1.9.6 HTTPv2 PRI Double-Free DoS");
  script_summary(english:"Checks the version of nginx.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in its response header, the
version of nginx hosted on the remote web server is 1.9.x prior to
1.9.6. It is, therefore, affected by a denial of service vulnerability
due to a double-free memory error in the HTTPv2 module that is
triggered when handling certain PRI packets. An unauthenticated,
remote attacker can exploit this, via a crafted RPI packet, to cause a
section of heap-based memory to be freed twice, which can result in
crashing the server.");
  # http://www.security-assessment.com/files/documents/advisory/Nginx%20ngx_destroy_pool%20HTTP2%20Double%20Free.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6f9e7f");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  # 1.9.6 announcement
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2015/000163.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx version 1.9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

if (version =~ "^[0-1]\.[0-8]\."){
  audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
}else if (ver_compare(ver:version, fix:"1.9.6", strict:FALSE) == -1){
  # Affected : < 1.9.6
  # Fixed    : 1.9.6
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.9.6' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
