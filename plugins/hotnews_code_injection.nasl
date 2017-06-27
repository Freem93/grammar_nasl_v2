#
# (C) Tenable Network Security, Inc.
#

# XXXX Untested
#
# Ref:
# From:   officerrr@poligon.com.pl
# Subject: HotNews arbitary file inclusion
# Date: January 4, 2004 3:45:59 AM CET
# To:   bugtraq@securityfocus.com


include("compat.inc");

if(description)
{
 script_id(11979);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2004-1796");
 script_osvdb_id(3332, 3405);

 script_name(english:"HotNews Multiple Script Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a vulnerability in a PHP application that may
allow for the execution of arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HotNews, a set of PHP scripts designed to set up
a newssystem for web pages.

It is possible this suite to make the remote host include php files hosted
on a third-party server.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of HotNews" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/03");
 script_cvs_date("$Date: 2014/04/23 16:29:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Checks for the presence of HotNews";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

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
if(!can_host_php(port:port))exit(0);


foreach dir (cgi_dirs())
 {
 w = http_send_recv3(item:string(dir, "/includes/hnmain.inc.php3?config[incdir]=http://xxxxxxxxxx/"),
 method:"GET", port:port);
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("http://xxxxxxxxxx/func.inc.php3" >< r)
  {
 	security_hole(port);
	exit(0);
  }
}
