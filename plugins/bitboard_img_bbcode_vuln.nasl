#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16191);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2005-0374");
 script_bugtraq_id(12248);
 script_osvdb_id(12921);

 script_name(english:"BiTBOARD IMG BBCode Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BiTBOARD, a web-based bulletin board
written in PHP. 

The remote version of this software is affected by a cross-site
scripting issue that may allow an attacker to steal the http cookies
of the regular users of the remote site to gain unauthorized access to
their account." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/135" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BiTBOARD 2.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/12");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines the version of BiTBOARD");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
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

 r = http_send_recv3(port: port, method: 'GET', item: url +"/index.php", exit_on_fail: 1);
 res = r[1] + r[2];
 if ( "the BiTSHiFTERS SDC" >< res )
 {
  if ( egrep(pattern:"BiTBOARD v([0.1]\..*|2\.[0-5]) Bulletin Board by.*the BiTSHiFTERS SDC</a>", string: res) ) {
	security_note(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
