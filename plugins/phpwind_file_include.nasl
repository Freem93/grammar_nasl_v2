#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16122);
 script_version("$Revision: 1.15 $");
 script_bugtraq_id(12207);
 script_osvdb_id(12888);

 script_name(english:"PHPWind Board faq.php skin Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPWind Board, a web-based bulletin board. 

There is a flaw in older versions of this software in the file
'faq.php' that could allow an attacker to gain a shell on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.54hack.info/txt/phpwind.doc" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPwind 2.0.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/09");
 script_cvs_date("$Date: 2012/10/01 23:25:59 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwind:phpwind");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of PHPWind Board.";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r, w;
 w = http_send_recv3(method:"GET", item:string(loc, "faq.php?skin=../../admin/manager&tplpath=admin"), port:port);
 if (isnull(w))exit(0);
 r = w[2];
 if("input type=text name=password size=40 value=" >< r) 
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

