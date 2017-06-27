#
# (C) Tenable Network Security, Inc.
#

#
# Ref: 
#  Date: Sat, 31 May 2003 13:58:58 +1200
#  From: Stephen Cope <mail@nonsense.kimihia.org.nz>
#  To: bugtraq@securityfocus.com
#  Subject: URLScan detection


include("compat.inc");


if (description)
{
 script_id(11699);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_bugtraq_id(7767);
 
 script_name(english: "URLScan for IIS Detection");
 script_summary(english: "Detects the presence of URLScan");

 script_set_attribute(attribute:"synopsis", value:"URLScan is installed.");
 script_set_attribute(attribute:"description", value:
"The remote web server is using URLScan to protect itself, which is a
good thing.

However since it is possible to determine that URLScan is installed,
an attacker may safely assume that the remote web server is Internet
Information Server.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jun/0");
 script_set_attribute(attribute:"solution", value:"None");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/05");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

#
# Method#1 : do a HTTP HEAD on a regular nonexistent page and
# a forbidden fruit, and compare the results (if UseFastPathReject
# is disabled, we will identify the remote urlscan server).
# 

r = http_send_recv3(port: port, method: 'HEAD', item:"/someunexistantstuff" + rand() + rand() + ".html");
res = tolower(r[2]);
if ("<!doctype" >< res || "<html>" >< res) exit(0);

r = http_send_recv3(port: port, method: 'HEAD', item: "/someunexistantstuff.exe");
res2 = tolower(r[2]);

flag = 0;
if( "<!doctype" >< res2 || "<html>" >< res2 ) { flag = 1; }

#
# Method#2 : Compare the results for a HTTP GET for a nonexistent
# page and a forbidden page (is UseFastPathReject is set, then we'll
# note several differences). 
# If UseFastPathReject is set, we will receive a very very small error
# message, whereas we will receive a much longer one if it's not
# 
r = http_send_recv3(port: port, method: 'GET', item:"/someunexistantantsutff" + rand() + rand() + ".html");
if (isnull(r) || r[0] !~ "^HTTP/[0-9]\.[0-9] 404 ") exit(0);

r2 = http_send_recv3(port: port, method: 'GET', item:"/someunexistantantsutff.exe");
if (isnull(r2) || r2[0] !~ "^HTTP/[0-9]\.[0-9] 404 ") exit(0);

if (strlen(r[2]) > 2 * strlen(r2[2]) && flag) security_note(port);
