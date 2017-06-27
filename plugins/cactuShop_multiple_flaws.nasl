#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15461);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id("CVE-2004-1881", "CVE-2004-1882");
  script_bugtraq_id(10019, 10020);
  script_osvdb_id(4785, 4786, 4787);
  
  script_name(english:"CactuShop 5.x Multiple Remote Vulnerabilities (XSS, SQLi)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host runs CactuShop, an e-commerce web application written
in ASP.

The remote version of this software is vulnerable to cross-site 
scripting due to a lack of sanitization of user-supplied-data in the 
script 'popuplargeimage.asp'.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

This version may also be vulnerable to SQL injection attacks in 
the scripts 'mailorder.asp' and 'payonline.asp'. The user-supplied 
input parameter 'strItems' is not filtered before being used in 
a SQL query. Thus, the query modification through malformed input 
is possible.

Successful exploitation of this vulnerability can enable an attacker
to execute commands in the system (via MS SQL the function xp_cmdshell)." );
  # http://marc.info/?l=bugtraq&amp;m=108075059013762&amp;w=2
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ebb7e5f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CactuShop 5.113 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/31");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:cactusoft:cactushop");
script_end_attributes();

  script_summary(english:"Checks CactuShop flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/ASP");
  exit(0);
}

#the code

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/popuplargeimage.asp?strImageTag=<script>foo</script> ", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

# Make sure this looks like CactuShop before checking for the XSS
if(
  egrep(pattern:'CACTUSHOP [0-9.]+ ASP SHOPPING CART', string:r) &&
  egrep(pattern:'<td align="center"><script>foo</script></td>', string:r)
)
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
