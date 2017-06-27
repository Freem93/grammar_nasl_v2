#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14183);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2004-0681", "CVE-2004-0682");
 script_bugtraq_id(10674, 10824);
 script_osvdb_id(7597, 7952, 7954, 7955, 8284, 8285);
 script_xref(name:"Secunia", value:"12026");
 script_xref(name:"Secunia", value:"12183");
 
 script_name(english: "Comersus Cart Multiple Input Validation Vulnerabilities (SQLi, XSS)");
 script_summary(english:"Checks for Comersus");

 script_set_attribute( attribute:"synopsis", value:
"The web application running on the remote host has multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Comersus Shopping Cart Software.

There is a flaw in this interface that allows an attacker to log in
as any user by using a SQL injection flaw in the code of
comersus_backoffice_login.php.

An attacker may use this flaw to gain unauthorized access on
this host, or to gain the control of the remote database.

In addition to this, the remote version of this software may be
vulnerable to other issues (see BID 10674)." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Jul/71"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Aug/14"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Jul/1245"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of the software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/06");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");

 script_copyright(english: "This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689);

if (! get_port_state(port)) exit(0);
if (! can_host_asp(port:port)) exit(0);
if (wont_test_cgi(port: port)) exit(0);

foreach dir (make_list( cgi_dirs()))
{
 r = http_send_recv3( port: port, method: 'POST',
	item:dir + "/comersus_backoffice_login.php",
	data: "adminName=admin%27&adminpassword=123456&Submit2=Submit",
	add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
 if (isnull(r)) exit(0);
 if (egrep(pattern: "Microsoft.*ODBC.*80040e14", string: r[2]))
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
 }
}
