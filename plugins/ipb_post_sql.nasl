#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(15778);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2004-1531");
  script_bugtraq_id(11703);
  script_osvdb_id(11929);

  script_name(english:"Invision Power Board sources/post.php qpid Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of Invision Power Board on the remote host suffers from a
flaw in 'sources/post.php' that allows injection of SQL commands into
the remote SQL database.  An attacker may use this flaw to gain
control of the remote database and possibly to overwrite files on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Nov/239" );
 script_set_attribute(attribute:"see_also", value:"http://forums.invisionpower.com/index.php?showtopic=154916" );
 script_set_attribute(attribute:"solution", value:
"Replace the 'sources/post.php' file with the one referenced in the
vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/18");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Detect Invision Power Board Post SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 w = http_send_recv3(method:"GET", item:string(path, "/index.php?act=Post&CODE=02&f=3&t=10&qpid=1'"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = w[2];

 if ("mySQL query error: select p.*,t.forum_id FROM ibf_posts p LEFT JOIN ibf_topics t ON (t.tid=p.topic_id)" >< res)
 {
  security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
