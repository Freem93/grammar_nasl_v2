#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15561);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2011/03/15 11:22:40 $");

 script_cve_id("CVE-2004-1622");
 script_bugtraq_id(11502);
 script_osvdb_id(11050);

 script_name(english:"UBB.threads dosearch.php SQL injection");
 script_summary(english:"SQL Injection in UBB.threads");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"There is a SQL injection issue in the remote version of UBB.threads
that may allow an attacker to execute arbitrary SQL statements on the
remote host and potentially overwrite arbitrary files there by sending
a malformed value to the 'Name' argument of the file 'dosearch.php'." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109839925207038&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("ubbthreads_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ubbthreads");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
 dir = matches[2];
 r = http_send_recv3(method:"GET", port:port, item: dir + "/dosearch.php?Name=42'", exit_on_fail:TRUE);
 res = r[2];
 if ( "mysql_fetch_array()" >< res )
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
