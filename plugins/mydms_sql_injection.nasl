#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14327);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2004-1732", "CVE-2004-1733");
 script_bugtraq_id(10996);
 script_osvdb_id(9083, 9084);

 script_name(english:"MyDMS < 1.4.3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MyDMS, an open source document management
system based on MySQL and PHP.

The remote version of this software is vulnerable to a SQL injection
bug that may allow any guest user to execute arbitrary SQL commands
against the remote database. There is also a directory traversal issue
that may allow logged users to read arbitrary files on the remote
host with the privileges of the HTTP daemon." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/299" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/313" );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/unixfocus/5JP0M0KDPK.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyDMS 1.4.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/22");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mydms:mydms");
script_end_attributes();

 
 summary["english"] = "SQL injection against the remote MyDMS installation";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
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

if ( ! can_host_php(port:port) ) exit(0);

init_cookiejar();
foreach dir (cgi_dirs())
{
 r = http_send_recv3(method: "GET", item:dir + "/op/op.Login.php?login=guest&sesstheme=default&lang=English", port:port);
if ( "mydms_" >< r[1]+r[2] )
{
 r = http_send_recv3(method: "GET", item:dir + "/out/out.ViewFolder.php?folderid='", port:port);
 if ("SELECT * FROM tblFolders WHERE id =" >< r[2] ) 
  {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
  }
 }
}
