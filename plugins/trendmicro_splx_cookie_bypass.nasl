#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24690);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id("CVE-2007-1168");
  script_bugtraq_id(22662);
  script_osvdb_id(33041);

  script_name(english:"Trend Micro ServerProtect for Linux splx_2376_info Cookie Authentication Bypass");
  script_summary(english:"Tries to bypass authentication with SPLX");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from an authentication bypass
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running ServerProtect for Linux, an antivirus
application for Linux-based servers from Trend Micro. 

The version of ServerProtect for Linux installed on the remote host
fails to check the validity of the session id in the 'splx_2376_info'
cookie before granting access to its administrative pages.  A remote
attacker can exploit this flaw to bypass authentication and gain full
control of the affected web application.");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=477
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4fa3bf6");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/460805/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/download/product.asp?productid=20");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:serverprotect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 14942);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:14942);

# Try to bypass authentication and gain access to a protected page.
set_http_cookie(name: "splx_2376_info", value: "1");
url = "/SProtectLinux/showpage.cgi?page=../html/splx_main.htm";
r = http_send_recv3(method: "GET", item:url, port:port);
if (isnull(r)) exit(0);


# There's a problem if we see the main frame.
if (
  "<title>Trend Micro ServerProtect for Linux</title>" >< r[2] &&
  'target="main" src="./showpage.cgi?page=../html/splx_content.htm"' >< r[2]
) security_hole(port);
