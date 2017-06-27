#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/3/09)

include("compat.inc");

if (description)
{
  script_id(12122);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2001-1195");
  script_bugtraq_id(3697);
  script_osvdb_id(4999);

  script_name(english:"Novell Groupwise Servlet Manager Default Password");
  script_summary(english:"Checks for NetWare servlet server default password");

  script_set_attribute(attribute:"synopsis", value:"The remote host is reachable with known credential.");
  script_set_attribute(attribute:"description", value:
"The Novell Groupwise servlet server is configured with a default
password.  As a result, users could be denied access to mail and other
servlet based resources. 

To test this finding:

https://<host>/servlet/ServletManager/

enter 'servlet' for the user and 'manager' for the password.");
  script_set_attribute(attribute:"solution", value:
"Change the default password.

Edit SYS:\JAVA\SERVLETS\SERVLET.PROPERTIES

Change the username and password in this section
servlet.ServletManager.initArgs=datamethod=POST,user=servlet,password=manager,bgcolor");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value: "http://www.securityfocus.com/bid/3697");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 David Kyger");
  script_family(english:"Netware");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:443);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

req = string("GET /servlet/ServletManager HTTP/1.1\r\nHost: ", get_host_name(), "\r\nAuthorization: Basic c2VydmxldDptYW5hZ2Vy\r\n\r\n");

debug_print(level:2, req);

buf = http_keepalive_send_recv(port:port, data:req);
if ( buf == NULL ) exit(0);

debug_print(level:2, buf);

pat1 = "ServletManager";
pat2 = "Servlet information";


    if(pat1 >< buf && pat2 >< buf)
    {
        security_warning(port:port);
    }
