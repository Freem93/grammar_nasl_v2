#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15621);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2001-1432");
 script_bugtraq_id(3772);
 script_xref(name:"OSVDB", value:"16980");

 script_name(english:"Cherokee Web Server URI Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to directory
traversal flaw when appending a '../' sequence to the web request.

Additionally, this version fails to drop root privileges after it 
binds to listen port.

Remote attacker can then submit specially crafted web request to 
browse any file on the server with root privileges." );
 # https://web.archive.org/web/20020221222542/http://archives.neohapsis.com/archives/vulnwatch/2001-q4/0085.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce6bb0e6" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cherokee 0.2.8 or newer as this reportedly fixes the issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/12/30");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for version of Cherokee");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([01]\.|2\.[0-7])[^0-9]", string:serv))
 {
   security_warning(port);
 }
