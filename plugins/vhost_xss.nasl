#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12094);
 script_version("$Revision: 1.22 $");
 script_cve_id("CVE-2004-2278");
 script_bugtraq_id(9860);
 script_osvdb_id(4207);
 
 script_name(english:"vHost < 3.10r1 Unspecified XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of vHost that is older 
than 3.10r1. There is a cross-site scripting vulnerability in 
this version that may allow an attacker to steal the cookies 
of the legitimate users of this site." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the vHost 3.10r1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/29");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 summary["english"] = "version test for vHost";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var	port;

function check(dir)
{
  local_var	r, time;
  time = unixtime();
  r = http_send_recv3(method: "GET", item:dir + "/vhost.php?action=logout&time=" + time, port:port, exit_on_fail: 1);

  if ("<!-- vhost" >< r[2] )
   {
    if ( egrep(pattern:"<!-- vhost ([12]\.|3\.([0-9][^0-9]|10[^r]))", string:r[2]) ) {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
    }
   }
 return(0);
}

port = get_http_port(default:80, php: 1);


foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
