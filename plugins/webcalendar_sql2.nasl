#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17142);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2005-0474");
 script_bugtraq_id(12581);
 script_osvdb_id(13918);

 script_name(english:"WebCalendar login.php webcalendar_session Cookie SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote version of WebCalendar contains a SQL injection
vulnerability that may allow an attacker to execute arbitrary SQL
statements against the remote database.  An attacker may be able to
leverage this issue to, for example, delete arbitrary database tables." );
 script_set_attribute(attribute:"see_also", value:"http://scovettalabs.com/wp-content/uploads/2008/02/scl-2005001.txt" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110868446431706&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 0.9.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/17");
 script_cvs_date("$Date: 2017/02/07 14:52:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Sends a malformed cookie to the remote host");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("webcalendar_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/webcalendar");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_kb_item("www/" +port+ "/webcalendar");
if (isnull(install)) audit(AUDIT_WEB_APP_NOT_INST, "WebCalendar", port);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 set_http_cookie(name: "webcalendar_session", value: "7d825292854146");
 r = http_send_recv3(method: "GET", item:dir + "/views.php", port:port, exit_on_fail:TRUE);
 if ( "<!--begin_error(dbierror)-->" >< r[2] )
 {
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   security_hole(port);
 }
}
else audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
