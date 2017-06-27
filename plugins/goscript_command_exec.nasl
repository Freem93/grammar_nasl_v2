#
# (C) Tenable Network Security, Inc.
#

# osvdb value submitted by David Maciejak

include("compat.inc");

if (description)
{
  script_id(14237);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/10/10 15:57:06 $");

  script_cve_id("CVE-2004-2776");
  script_bugtraq_id(10853);
  script_osvdb_id(8935);

  script_name(english:"GoScript go.cgi Arbitrary Command Execution");
  script_summary(english:"Goscript command execution detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI script that is affected by a remote
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running GoScript.  The installed version fails to
properly sanitize user-supplied input to the 'go.cgi' script.  An
unauthenticated, remote attacker could exploit this flaw to execute
arbitrary commands on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/38");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
server_name = http_server_header(port:port);
if ('Monitorix' >< server_name) exit(0, "The Monitorix install listening on port "+port+" is not affected as it does not include GoScript's go.cgi script.");

http_check_remote_code (
			check_request:"/go.cgi|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
                        port:port
			);

audit(AUDIT_LISTEN_NOT_VULN, "HTTP Server", port);
