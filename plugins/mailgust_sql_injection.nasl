#
# Script Written By Ferdy Riphagen (GPL)
# <f.riphagen@nsec.nl>
#
# Changes by Tenable:
# - Revised plugin title (2/11/2009)


include("compat.inc");

if (description) {
script_id(19947);
script_version("$Revision: 1.16 $");

script_cve_id("CVE-2005-3063");
script_bugtraq_id(14933);
  script_osvdb_id(19679);

script_name(english:"Mailgust Password Reminder email Field SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running MailGust, a mailing list
manager, newsletter distribution tool and message board. 

A vulnerability was identified in MailGust that could be exploited by
remote attackers to execute arbitrary SQL commands provided PHP's
'magic_quotes_gpc' setting is disabled." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/maildisgust.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/25");
 script_cvs_date("$Date: 2011/12/14 22:22:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


summary["english"] = "Check if MailGust is vulnerable to SQL Injection.";
script_summary(english:summary["english"]);

script_category(ACT_ATTACK);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2005-2011 Ferdy Riphagen");

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");
script_require_keys("www/PHP");
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/mailgust", "/forum", "/maillist", "/gust", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 # Make sure the affected script exists.
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (isnull(res)) exit(0);

 if (egrep(pattern:">Powered by <a href=[^>]+>Mailgust", string:res)) {
  req = string(
  "POST ",dir,"/index.php HTTP/1.0\r\n",
  "Content-Length: 64\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
  "method=remind_password&list=maillistuser&email='&showAvatar=\r\n\r\n");

  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL)exit(0);

  if(egrep(pattern: "SELECT.*FROM.*WHERE", string:recv))
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
 }
}
