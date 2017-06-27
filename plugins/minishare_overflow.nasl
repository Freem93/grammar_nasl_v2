#
# written by Gareth Phillips - SensePost PTY ltd (www.sensepost.com)
#
# Changes by Tenable:
# - detect title to prevent false positives
# - fix version detection
# - added CVE and OSVDB xrefs.
# - revised plugin title, changed family, update output formatting (8/18/09)



include("compat.inc");

if(description)
{
 script_id(18424);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2004-2271");
 script_bugtraq_id (11620);
 script_osvdb_id(11530);

 script_name(english:"MiniShare Webserver HTTP GET Request Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote buffer overflow 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"MiniShare 1.4.1 and prior versions are affected by a buffer overflow 
flaw. A remote attacker could execute arbitrary commands by sending a
specially crafted file name in a the GET request.

Version 1.3.4 and below do not seem to be vulnerable." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Nov/248" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MiniShare 1.4.2 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Minishare 1.4.1 Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/07");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"MiniShare webserver buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 SensePost");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Code Starts Here
#

# supress warnings
function debug_print() {
  local_var v;
  v = _FCT_ANON_ARGS[0];
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if ("<title>MiniShare</title>" >!< res)
  exit (0);

if (egrep (string:res, pattern:'<p class="versioninfo"><a href="http://minishare\\.sourceforge\\.net/">MiniShare 1\\.(3\\.([4-9][^0-9]|[0-9][0-9])|4\\.[0-1][^0-9])'))
  security_hole (port);
}
