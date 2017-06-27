#
# This script is a mix between the work done by 
# Sarju Bhagat <sarju@westpoint.ltd.uk> and
# Martin O'Neal of Corsaire (http://www.corsaire.com)
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, minor fixes to description (1/13/2009)


include("compat.inc");

if(description)
{
 script_id(12300);
 script_bugtraq_id(10275, 8050);
 script_osvdb_id(5891);
 script_cve_id("CVE-2004-0050");

 script_name(english:"Inktomi Search MS-DOS Device Name Request Path Disclosure");

 script_version ("$Revision: 1.11 $");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"This web server is running a vulnerable version of Verity Ultraseek 
(formerly Inktomi Search).

Certain requests using MS-DOS special file names such as NUL can cause
a python error. The error message contains sensitive information such
as the physical path of the webroot. This information may be useful to
an attacker." );
 script_set_attribute(attribute:"see_also", value:"http://www.corsaire.com/advisories/c040113-001.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Verity Ultraskeek 5.2.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/05");
 script_cvs_date("$Date: 2011/03/17 01:57:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Checks for a Inktomi Search vulnerability";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2011 Westpoint Limited and Corsaire Limited");
  
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8765);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#
# The script code starts here
#

port = get_http_port(default:8765);
if(!get_port_state(port))exit(0);

# Check that the remote web server is UltraSeek, as 
# some other servers may crash the host when requested
# for a DOS device.
banner = get_http_banner(port:port);
if ( banner == NULL || "Server: Ultraseek" >!< banner ) exit(0);


req = http_get(item:"/nul", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if ( "httpsrvr.py:1033" >!< res ||
     "500 Internal Server Error" >!< res ) exit(0);

w = egrep(pattern:"directory", string:res);
if(w)
{
  webroot = ereg_replace(string:w, pattern:"^.*'(.*)'.*$", replace:"\1");
  if (webroot == w) exit(0);
  report = string(
    "\n",
    "The remote web root is : " + w + "\n",
    "\n"
  );
  security_warning(port:port, extra:report);
}
