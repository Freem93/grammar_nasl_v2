#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# References:
# To: bugtraq@securityfocus.com
# From: rsanmcar@alum.uax.es
# Subject: BOOZT! Standard 's administration cgi vulnerable to buffer overflow
# Date: Sat, 5 Jan 2002 18:04:48 GMT
#
# Affected:
# Boozt 0.9.8alpha
#

include("compat.inc");

if (description)
{
 script_id(11082);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2002-0098");
 script_bugtraq_id(3787, 6281);
 script_osvdb_id(2017);

 script_name(english:"Boozt index.cgi Banner Creation Name Field Overflow");
 script_summary(english:"Buffer overflow in Boozt AdBanner index.cgi");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the web
server.");
 script_set_attribute(attribute:"description", value:
"The version of Boozt AdBanner installed on the remote web server fails
to check the length of the 'name' POST parameter of the 'index.cgi'
script before copying the supplied value to internal arrays.  An
unauthenticated, remote attacker can leverage this issue to overflow a
buffer and crash the affected web server or even execute arbitrary code
on the affected host.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jan/36");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

d1 = sort(make_list(cgi_dirs(), ""));
d2 = make_list("/boozt", "");
d3 = make_list("/admin", "");

function find_boozt(port)
{
  local_var	i1, i2, i3, prev, u, r;
  foreach i1 (d1)
  {
    if (i1 == prev) continue;
    prev = i1;
    foreach i2 (d2)
      foreach i3 (d3)
      {
        u = strcat(i1, i2, i3, "/index.cgi");
	r = http_send_recv3(port: port, method: 'GET', item: u, exit_on_fail: 1);
        if (r[0] =~ "^HTTP.* 200 .*" && "BOOZT Adbanner system" >< r[2]) # ?
	   return(u);
      }
  }
  return 0;
}

#######

port = get_http_port(default:80);

bz = find_boozt(port: port);
if (! bz) exit(0, "Boozt is not installed in port "+port+".");

r = http_send_recv3( port: port, item: bz, method: 'POST',
    		     data: strcat('name=', crap(1025), '\r\n\r\n'),
		     exit_on_fail: 1,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
# MA 2008-10-13: the old version set Content-Length=1030, which is wrong.

if (r[0] =~ "^HTTP/[0-9.]+ +5[0-9][0-9] ")
{
  security_hole(port);
  exit(0);
}

