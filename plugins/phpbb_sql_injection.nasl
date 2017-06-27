#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11767);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");

 script_cve_id("CVE-2003-0486");
 script_bugtraq_id(7979);
 script_osvdb_id(2186);
 
 script_name(english:"phpBB viewtopic.php topic_id Parameter SQL Injection");
 script_summary(english:"SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection.");
 script_set_attribute(attribute:"description", value:
"There is a flaw in the version of phpBB hosted on the remote web server
that may allow anyone to inject arbitrary SQL commands, which could in
turn be used to gain administrative access on the remote host or to
obtain the MD5 hash of the password of any user.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("phpbb_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpBB");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
dir     = matches[2];

r = http_send_recv3(method: "GET", item:dir + "/viewtopic.php?sid=1&topic_id='", port:port);
if (isnull(r)) exit(0);
buf = strcat(r[0], r[1], '\r\n', r[2]);

if("SELECT t.topic_id, t.topic_title, t.topic_status" >< buf)
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

