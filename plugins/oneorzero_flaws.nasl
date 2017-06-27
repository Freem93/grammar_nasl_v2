#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Frog Man" <leseulfrog@hotmail.com>
#  To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
#  Date: Thu, 15 May 2003 19:06:40 +0200
#  Subject: [VulnWatch] OneOrZero Security Problems (PHP)


include("compat.inc");

if (description)
{
 script_id(11643);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2003-0303");
 script_bugtraq_id(7609, 7611);
 script_osvdb_id(10102);

 script_name(english:"OneOrZero Helpdesk tupdate.php sg Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OneOrZero, an online helpdesk.

There are multiple flaws in this software that could allow 
an attacker to insert arbitrary SQL commands in the remote 
database, or even to gain administrative privileges on this 
host." );
 script_set_attribute(attribute:"solution", value:
"Unofficial patches are available at http://www.phpsecure.info" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/15");
 script_cvs_date("$Date: 2016/12/07 20:46:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines OneOrZero is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
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
if(!can_host_php(port:port)) exit(0,"The remote host does not support PHP.");

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/help", "/support", "/supporter", "/support/helpdesk", "/helpDesk", "/helpdesk", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach d (dirs)
{
  res = http_send_recv3(method:"GET", item:d + "/supporter/tupdate.php?groupid=change&sg='", port:port);
  if( isnull(res) ) exit(1,"Null response to tupdate.php request.");
  if("SQL" >< res[2] && "' where id='" >< res[2])
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
}
