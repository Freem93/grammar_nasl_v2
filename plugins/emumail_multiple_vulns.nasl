#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");


if(description)
{
 script_id(12095);
 script_cve_id("CVE-2004-2334", "CVE-2004-2385");
 script_bugtraq_id(9861);
 script_osvdb_id(4203, 4204, 4972);
 
 script_version("$Revision: 1.20 $");

 script_name(english:"Emumail WebMail Multiple Remote Vulnerabilities (XSS, Disc)");
 script_summary(english:"version test for Emumail");
 
 script_set_attribute(attribute:"synopsis",value:
"A webmail application running on the remote host has multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote host is running a
vulnerable version of EMUMAIL WebMail.

There are several vulnerabilities in this version, ranging 
from information disclosure to cross-site scripting vulnerabilities. 
These issues may allow an attacker to trick a logged-in user 
into providing access to this system." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/11");
 script_cvs_date("$Date: 2015/02/03 17:40:01 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function check(dir, port)
{
  local_var req, res;

  req = string(dir, "/emumail.fcgi");
  res = http_send_recv3(method:"GET", item:req, port:port);
  if (isnull(res)) exit(0);

  if ("Powered by EMU Webmail" >< res[2])
   {
    if ( egrep(pattern:"(Powered by|with) EMU Webmail ([0-4]\.|5\.([01]\.|2\.[0-7][^0-9]))", string:res[2]) ) {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
    }
   }
 return(0);
}


#
# Execution begins here
#
port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 check(dir:dir, port:port);
}
