#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77246);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2014-3556");
  script_bugtraq_id(69111);
  script_osvdb_id(109849);

  script_name(english:"nginx < 1.6.1 / 1.7.4 SMTP STARTTLS Command Injection");
  script_summary(english:"Checks the version of nginx.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the server response header,
the version of nginx installed on the remote host is 1.5.6 or higher,
1.6.x prior to 1.6.1, or 1.7.x prior to 1.7.4. It is, therefore,
affected by a command injection vulnerability.

A flaw exists in the function 'ngx_mail_smtp_starttls' within the file
'src/mail/ngx_mail_smtp_handler.c' whereby input to the STARTTLS
command is not properly sanitized. This could allow a remote attacker
in a privileged network position to obtain sensitive information by
injecting commands into an SSL session.

Note that this issue is exploitable only when nginx is used as an SMTP
proxy.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000144.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/download/patch.2014.starttls.txt");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.6");
  script_set_attribute(attribute:"solution", value:"Apply the patch manually, or upgrade to nginx 1.6.1 / 1.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (version =~ "^1(\.5)?$" || version =~ "^1(\.6)?$" || version =~ "^1(\.7)?$")  audit(AUDIT_VER_NOT_GRANULAR, "nginx", port, version);

# Affected : 1.5.6 - 1.7.3
# Fixed    : 1.6.1 , 1.7.4
if (
  version =~ "^1\.5\.([6-9]([^0-9]|$)|[1-9]\d{1,})" ||
  version =~ "^1\.6\.0([^0-9]|$)" ||
  version =~ "^1\.7\.[0-3]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.6.1 / 1.7.4' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
