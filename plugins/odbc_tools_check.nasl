#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (3/27/2009)

include("compat.inc");

if (description)
{
  script_id(11872);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/11/18 21:03:58 $");

  script_osvdb_id(3512, 41063);

  script_name(english:"Microsoft IIS ODBC Tool getdrvrs.exe DSN Creation");
  script_summary(english:"Checks for the presence of ODBC tools");

  script_set_attribute(attribute:"synopsis", value:"Sensitive data can be read or written on the remote host.");
  script_set_attribute(attribute:"description", value:
"ODBC tools are present on the remote host.

ODBC tools could allow a malicious user to hijack and redirect ODBC
traffic, obtain SQL user names and passwords or write files to the
local drive of a vulnerable server.

Example: http://www.example.com/scripts/tools/getdrvrs.exe");
  script_set_attribute(attribute:"solution", value:"Remove ODBC tools from the /scripts/tools directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2015 David Kyger");
  script_family(english:"CGI abuses");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);



flag = 0;

warning = "The following ODBC tools were found on the server:";




port = get_http_port(default:80);

if(get_port_state(port)) {

   fl[0] = "/scripts/tools/getdrvrs.exe";
   fl[1] = "/scripts/tools/dsnform.exe";

   for(i=0;fl[i];i=i+1)
   {
    if(is_cgi_installed_ka(item:fl[i], port:port))
	{
        warning = warning + string("\n", fl[i]);
        flag = 1;
        }
   }
    if (flag > 0) {
        security_hole(port:port, extra:warning);
        } else {
          exit(0);
        }
}


