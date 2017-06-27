#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20376);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-4586");
 script_bugtraq_id(16077);
 script_osvdb_id(22039);
  
 script_name(english:"PHPSurveyor Multiple SQL Injections");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPSurveyor, a set of PHP scripts that
interact with MySQL to develop surveys, publish surveys and collect
responses to surveys. 

The remote version of this software is prone to a SQL injection flaw. 
Using specially crafted requests, an attacker can manipulate database
queries on the remote system." );
  # http://sourceforge.net/project/shownotes.php?release_id=381050&group_id=74605
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e74534" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPSurveyor version 0.991 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/02");
 script_cvs_date("$Date: 2012/09/14 21:55:52 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpsurveyor:phpsurveyor");
script_end_attributes();

 
 summary["english"] = "Checks for PHPSurveyor sid SQL injection flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/PHP");
 exit(0);
}

#
# the code
#

 include("global_settings.inc");
 include("http_func.inc");
 include("http_keepalive.inc");
 include("misc_func.inc");

 port = get_http_port(default:80);
 if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
 if (!can_host_php(port:port) ) exit(0);

 # Check a few directories.
 if (thorough_tests) dirs = list_uniq(make_list("/phpsurveyor", "/survey", cgi_dirs()));
 else dirs = make_list(cgi_dirs());

 foreach dir (dirs)
 { 
  req = http_get(item:string(dir,"/admin/admin.php?sid=0'"),port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(egrep(pattern:"mysql_num_rows(): supplied argument is not a valid MySQL .+/admin/html.php", string:r))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
 }
