#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12064);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2004-0293");
 script_bugtraq_id(9670);
 script_osvdb_id(3978, 4018);
 
 script_name(english:"ShopCartCGI Multiple Script Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by 
multiple arbitrary file access issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ShopCartCGI - a set of CGIs designed to set
up an on-line shopping cart. 

The version of ShopCartCGI on the remote host fails to sanitize input
to several of its CGI scripts before using it to read and display
files.  An unauthenticated, remote attacker can leverage these issues
to read arbitrary files on the remote web server with the privileges of
the web user." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/454");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/17");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks ShopCart");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
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

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 w = http_send_recv3(method:"GET", port: port,
   item: strcat(dir,"/gotopage.cgi?4242+../../../../../../../../../../../../../etc/passwd"));
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 buf = strcat(w[0], w[1], '\r\n', w[2]);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_warning(port);
	exit(0);
 }

 if (thorough_tests){
   w = http_send_recv3(method:"GET", port: port,
     item: strcat(dir,"/genindexpage.cgi?4242+Home+/../../../../../../../../../../../../../etc/passwd"));
   if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
   buf = strcat(w[0], w[1], '\r\n', w[2]);

   if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
   	security_warning(port);
  	exit(0);
   }
 }
}
