#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19697);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-4806");
  script_bugtraq_id(14788);
  script_osvdb_id(19307, 19308, 19309);

  script_name(english:"Sun Java System Web Proxy Server Multiple Unspecified Remote DoS");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is prone to a denial of service attack." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Java System Web Proxy Server / Sun ONE Web
Proxy Server. 

According to its banner, the installed Web Proxy Server reportedly
suffers from an unspecified remote denial of service vulnerability. 
By exploiting this flaw, an attacker could cause the affected
application to fail to respond to further requests." );
  # http://web.archive.org/web/20060523234118/http://sunsolve.sun.com/search/document.do?assetkey=1-26-101913-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e566f57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Web Proxy Server 3.6 Service Pack 8 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/14");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/09");
  script_set_attribute(attribute:"patch_publication_date", value: "2005/09/08");
  script_cvs_date("$Date: 2013/08/26 22:28:53 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_summary(english:"Checks for unspecified remote denial of service vulnerability in Sun Java System Web Proxy Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

banner = http_get_cache(port:port, item: "/", exit_on_fail: 1);
if (
  "Web-Proxy-Server/" >< banner &&
  banner =~ "^Forwarded: .* \(Sun-.+-Web-Proxy-Server/([0-2]\..*|3\.([0-5]\..*|6(\)|-SP[0-7])))"
) security_warning(port);
