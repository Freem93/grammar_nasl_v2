#
# This script  written by deepquest <deepquest@code511.com>
#
# Ref: 
#  Date: 4 sep , 2003  7:07:39  AM
#  From: cyber_talon <cyber_talon@hotmail.com>
#  Subject: EZsite Forum Discloses Passwords to Remote Users
#
# Changes by Tenable:
# - Revised plugin title (1/02/2009)
# - Added VDB references (1/02/2009)

include("compat.inc");

if(description)
{
 script_id(11833);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/10/21 20:34:20 $");
 script_name(english:"EZsite Forum Discloses Passwords to Remote Users");
 # script_cve_id("CVE-MAP-NOMATCH");
 script_osvdb_id(51080);
 # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
 # Also, I've not found a bugtraq ID for this vulnerability
 # X-Force 13107, SecurityTracker 1007632, no CVE/BID (bm, january 2009)
 
 script_set_attribute(attribute:"synopsis", value:
"Credentials may be exposed by the remote web application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running EZsite Forum.

It is reported that this software stores usernames and passwords in
plaintext form in the 'Database/EZsiteForum.mdb' file. A remote user
can reportedly download this database." );
 script_set_attribute(attribute:"solution", value:
"No solution was available at the time. Configure your web server
to disallow the download of .mdb files." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/04");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for EZsiteForum.mdb password database";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 deepquest");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

dirs = make_list(cgi_dirs());

foreach d (dirs)
{
 req = http_get(item:string(d, "/forum/Database/EZsiteForum.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
