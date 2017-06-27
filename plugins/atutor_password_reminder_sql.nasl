#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#



include("compat.inc");

if (description) {
  script_id(19765);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-2954");
  script_bugtraq_id(14831);
  script_osvdb_id(19411);

  name["english"] = "ATutor Password Reminder SQL Injection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP script vulnerable to a SQL injection
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ATutor, an open source, web-based, Learning
Content Management System (LCMS) designed with accessibility and
adaptability in mind. 

The remote version of this software contains an input validation flaw
in the 'password_reminder.php' script.  This vulnerability occurs only
when 'magic_quotes_gpc' is set to off in the 'php.ini' configuration
file.  A malicious user can exploit this flaw to manipulate SQL
queries and steal any user's password." );
 # https://web.archive.org/web/20060524132340/http://retrogod.altervista.org/atutor151.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?173b81e7");
 script_set_attribute(attribute:"solution", value:
"Upgrade to ATutor 1.5.1 pl1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/14");
 script_cvs_date("$Date: 2017/05/02 23:36:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for SQL injection in password_reminder.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"(C) 2005-2017 Josh Zlatin-Amishav");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
      
postdata = string(
  "form_password_reminder=true&",
  "form_email=%27", SCRIPT_NAME, "&",
  "submit=Submit"
);

foreach dir ( cgi_dirs() )
{
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/password_reminder.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    "ATutor" >< res &&
    '<input type="hidden" name="form_password_reminder"' >< res
  ) {
    req = string(
      "POST ", dir, "/password_reminder.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    if ( "mysql_fetch_assoc(): supplied argument is not a valid MySQL result resource" >< res) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
