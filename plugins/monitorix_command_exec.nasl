#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71212);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/12/12 21:01:48 $");

  script_cve_id("CVE-2013-7070");
  script_bugtraq_id(64178);
  script_osvdb_id(100531);

  script_name(english:"Monitorix Built-in HTTP Server Remote Command Execution");
  script_summary(english:"Tries to exploit remote command execution vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by a remote command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Monitorix built-in HTTP server does not properly sanitize
HTTP GET request strings, allowing for remote, arbitrary command
execution via a specially crafted HTTP request."
  );
  script_set_attribute(attribute:"see_also", value:"https://github.com/mikaku/Monitorix/issues/30");
  script_set_attribute(attribute:"see_also", value:"http://www.monitorix.org/news.html#N331");
  script_set_attribute(attribute:"solution", value:"Upgrade to Monitorix 3.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:monitorix:monitorix");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, embedded:TRUE);

server_name = http_server_header(port:port);
if ('Monitorix' >!< server_name) audit(AUDIT_NOT_LISTEN, "Monitorix HTTP Server", port);

http_check_remote_code(
  port:port,
  embedded:TRUE,
  check_request:"|id|",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id"
);
audit(AUDIT_LISTEN_NOT_VULN, "Monitorix HTTP Server", port);
