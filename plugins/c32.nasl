#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10389);
 script_version ("$Revision: 1.30 $");

 script_cve_id("CVE-2000-0429");
 script_bugtraq_id(1153);
 script_osvdb_id(294);
 
 script_name(english:"Cart32 Backdoor Password Arbitrary Command Execution");
 script_summary(english:"Determines the presence of Cart32");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A web application running on the remote host has a backdoor."
 );
 script_set_attribute(attribute:"description", value:
"The Cart32 e-commerce shopping cart is installed. This software
contains multiple security flaws.

There is a backdoor password of 'wemilo' in cart32.exe. This backdoor
allows a remote attacker to run arbitrary commands in the context of
the web server, and access credit card information.

Additionally, it may be possible to change the administrator password
by going directly to :

/c32web.exe/ChangeAdminPassword" );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Apr/236"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Cart32 version 5.0 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/27");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

foreach dir (cgi_dirs())
{
 url = string(dir, "/cart32.exe");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if ( isnull(res) ) exit(0);
 if ( egrep(pattern:"<title>Cart32 [0-2]\.", string:res) )
	{
	security_hole(port);
	exit(0);
	}
}
	
