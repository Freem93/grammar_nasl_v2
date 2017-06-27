#
# This script was written by Randy Matz <rmatz@ctusa.net>
#

# Changes by Tenable:
# - Revised plugin title (4/7/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(11230);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(4785);
 script_osvdb_id(27060);

 script_name(english:"Stronghold swish Search Script Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability was reported in a 
sample script provided with Red Hat's Stronghold web server. 
A remote user can determine the web root directory path.

A remote user can send a request to the Stronghold sample script 
swish to cause the script to reveal the full path to the webroot directory. 

Apparently, swish may also display system-specific information in the 
HTML returned by the script" );
 script_set_attribute(attribute:"solution", value:
"remove it" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/21");
 script_cvs_date("$Date: 2011/03/15 19:26:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of cgi-bin/search");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Randy Matz");
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

if (is_cgi_installed_ka(port:port, item:"/search"))
{
  req = http_get(item:"/search", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);
   if(egrep(pattern:".*sourcedir value=?/.*stronghold.*", string:r))
     {
     security_warning(port);
     exit(0);
     }
}

foreach dir (cgi_dirs())
{
 if (is_cgi_installed_ka(port:port, item:string(dir, "/search")))
 {
  req = http_get(item:string(dir, "/search"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if(r == NULL)exit(0);
  if(egrep(pattern:"sourcedir value=./.*stronghold.*", string:r))
     {
     security_warning(port);
     exit(0);
     }
  }
}
