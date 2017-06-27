#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18628);
 script_version("$Revision: 1.12 $");

 script_bugtraq_id(14099);
 script_osvdb_id(11025);

 script_name(english:"YaPiG Password Protected Directory Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The remote version of this software contains a flaw that can let a
malicious user view images in password protected directories. 
Successful exploitation of this issue may allow an attacker to access
unauthorized images on a vulnerable server." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=842990&group_id=93674&atid=605076" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=843736&group_id=93674&atid=605076" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/16");
 script_cvs_date("$Date: 2011/11/28 21:39:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for YaPiG version");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
	res = http_get_cache(item:string(dir, "/"), port:port);
	if (isnull(res)) exit(0);

	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9]($|[^0-9])|9([0-3]|4[a-u]))", string:res))
 	{
 		security_warning(port);
		exit(0);
	}
 
}
