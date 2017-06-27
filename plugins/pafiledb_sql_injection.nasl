#
# (C) Tenable Network Security, Inc.
#

# Date: Sun, 23 Mar 2003 16:13:37 -0500
# To: bugtraq Security List <bugtraq@securityfocus.com>
# From: flur <flur@flurnet.org>
# Subject: paFileDB 3.x SQL Injection Vulnerability


include("compat.inc");

if (description)
{
 script_id(11478);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(7183);
 script_osvdb_id(58502);
 
 script_name(english:"paFileDB pafiledb.php Multiple Parameter SQL Injection");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
several SQL injection issues." );
 script_set_attribute(attribute:"description", value:
"The remote installation of paFileDB is vulnerable to SQL injection
attacks because of its failure to sanitize input to the 'id' and
'rating' parameters to the 'pafiledb.php' script.  An attacker may use
this flaw to control your database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/316053" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
 script_cvs_date("$Date: 2011/03/12 01:05:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if pafiledb is vulnerable to a SQL injection");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencies("pafiledb_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/pafiledb");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];

 url = string(d, "/pafiledb.php?action=rate&id=1&rate=dorate&ratin=`");
 r = http_send_recv3(method:"GET",item:url, port:port);
 if (isnull(r)) exit(0, "The web server did not answer");
 
 if("UPDATE pafiledb_files SET file_rating" >< r[2])
   {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
   }
}

