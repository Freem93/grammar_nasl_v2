#
# This script was written by Thomas Reinke <reinke@securityspace.com>,
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, updated solution, output formatting (9/18/09)


include("compat.inc");

if(description)
{
 script_id(10947);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2002-0185");
 script_bugtraq_id(4656);
 script_osvdb_id(775);
 
 script_name(english:"mod_python < 2.7.8 Module Importing Privilege Function Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a module that is vulnerable to 
a code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the Apache mod_python module which is version
2.7.6 or older.

These versions allow a module which is indirectly imported by a 
published module to then be accessed via the publisher, which allows 
remote attackers to call possibly dangerous functions from the 
imported module." );
 script_set_attribute(attribute:"see_also", value:"http://www.modpython.org/pipermail/mod_python/2002-April/012512.html" );
 script_set_attribute(attribute:"see_also", value:"http://lwn.net/alerts/Conectiva/CLA-2002:477.php3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to mod_python 2.7.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/02");
 script_cvs_date("$Date: 2011/03/17 16:19:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for version of Python");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2011 Thomas Reinke");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:".*mod_python/(1.*|2\.([0-6]\..*|7\.[0-6][^0-9])).*", string:serv))
 {
   security_hole(port);
 }
}
