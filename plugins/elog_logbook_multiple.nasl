#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16469);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-0439", "CVE-2005-0440");
 script_bugtraq_id(12556, 12639, 12640);
 script_osvdb_id(13812, 13813);

 name["english"] = "ELOG Web Logbook < 2.5.7 Multiple Remote Vulnerabilities (OF, Traversal)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ELOG Web Logbook, a free webinterface
logbook. 

According to its banner, the version of ELOG Web Logbook installed on
the remote host contains a buffer overflow that can be triggered when
handing attachment with names longer than 256 characters to execute
code on the remote host subject to the permissions under which ELOG
operates. 

In addition, it is possible to retrieve a copy of the application's
config file and discover a form of its write password.  By default,
the value is encoded using Base-64, although it might be encrypted if
elog was compiled with '-DHAVE_CRYPT'." );
 script_set_attribute(attribute:"see_also", value:"http://midas.psi.ch/elogs/Forum/941" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.5.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/14");
 script_cvs_date("$Date: 2011/03/14 21:48:03 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Determines the presence of ELOG Web Logbook";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var port;

port = get_http_port(default:80);

function check(url)
{
 local_var r, res;

 r = http_send_recv3(method:"GET", item:url +"/?cmd=Config", port:port);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ( egrep(pattern:"^<center><a class=.*Goto ELOG home page.*midas\.psi\.ch/elog/.*ELOG V([0-1]\.|2\.([0-4]\.|5\.[0-6][^0-9]))", string:res) ) 
 {
        security_hole(port);
        exit(0);
 }
}

check(url:"/elog");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
