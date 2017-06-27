#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11758);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(7535);

 script_name(english:"eLDAPo index.php Plaintext Password Disclosure");
 script_summary(english:"Checks for eLDAPo");

 script_set_attribute(attribute:"synopsis",value:
"A web application running on the remote host has an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is hosting eLDAPo, a PHP-based CGI suite designed
to perform LDAP queries.

This application stores the passwords to the LDAP server in plaintext
in its source file. An attacker can read the source code of index.php
and use the information contained to gain credentials on a third-party
server.");
 script_set_attribute(
   attribute:"solution",
   value:"Upgade to eLDAPo 1.18 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/listing.php");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);

 if ("images/eLDAPo.jpg" >< res[2])
 {
  if(egrep(pattern:".*images/eLDAPo\.jpg.*V (0\.|1\.([0-9][^0-9]|1[0-7][^0-9]))", 
  	   string:res[2]))
	   {
	    security_warning(port);
	   }
     exit(0);	   
 }
}
