#
# (C) Tenable Network Security, Inc.
#
# Ref:
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Subject: [VulnWatch] GTcatalog (PHP)
# Message-ID: <F6zCrxpPKjnkJher0wL000598fc@hotmail.com>
#


include("compat.inc");

if(description)
{
 script_id(11319);
 script_bugtraq_id(6998);
 script_osvdb_id(51201, 51202);
 script_version ("$Revision: 1.18 $");

 script_name(english:"GTcatalog index.php custom Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains software that may allow for the
execution of arbitrary code." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using GTcatalog.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

In addition, making a direct request for 'password.inc' may reveal the
administrator password, although Nessus has not checked for this." );
 script_set_attribute(attribute:"solution", value:
"See http://www.phpsecure.org/ or contact the vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/04");
 script_cvs_date("$Date: 2014/04/23 16:40:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks for the presence of index.php");

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 local_var r, w;
 w = http_send_recv3(method:"GET", item:string(loc, "/index.php?function=custom&custom=http://xxxxxxxx/1"), port:port);			
 if (isnull(w)) exit(0);
 r = w[2];
 if(egrep(pattern:".*http://xxxxxxxx/1.custom.inc", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
{
 dirs = make_list(dirs, string(d, "/gtcatalog"), string(d, "/GTcatalog"));
}

dirs = make_list(dirs, "", "/gtcatalog", "/GTcatalog");



foreach dir (dirs)
{
 check(loc:dir);
}
