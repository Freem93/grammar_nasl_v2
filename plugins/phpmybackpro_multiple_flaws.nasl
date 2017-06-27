#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14787);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(11103);
 script_osvdb_id(9527);

 script_name(english:"phpMyBackupPro < 1.0.0 Unspecified Input Validation Issues");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be using phpMyBackupPro. 

It is reported that the remote version of this software is prone to 
multiple security weaknesses regarding user input validation. 

An attacker may use these issues to gain access to the application or 
to access the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.0 of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/30");
 script_cvs_date("$Date: 2012/09/10 21:39:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmybackuppro:phpmybackuppro");
script_end_attributes();

 script_summary(english:"Fetches the version of phpMyBackupPro");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  r = http_send_recv3(method: "GET", item:dir + "/index.php", port:port);
  if (isnull(r)) exit(0);
  if ( "phpMyBackupPro" >< r[2] &&    
       egrep(pattern:"<title>phpMyBackupPro 0\.([0-5]\.[0-9]|6\.[0-2])</title>", string:r[2]) )
	{
	 security_hole(port);
	 exit(0);
	}
 }
