#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20378);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-4264");
  script_bugtraq_id(15853);
  script_osvdb_id(21730);

  script_name(english:"PHP Support Tickets index.php Multiple Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerability in PHP Support Tickets");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Support Tickets, an open source support
ticketing system written in PHP. 

The installed version of PHP Support Tickets does not validate input
to the 'username' or 'password' parameters of the 'index.php' script
before using it in a database query.  An attacker may be able to
leverage this issue to manipulate SQL queries to, for example, bypass
authentication and gain administrative access to the affected
application." );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor as reportedly there is a patch to fix the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/10");
 script_cvs_date("$Date: 2013/01/18 22:57:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:triangle_solutions:php_support_tickets");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0, php: 1);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpsupporttickets", "/helpdesk", "/support", "/tickets", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check the main index.php page.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it looks like PHP Support Tickets' login form...
  if (
    '<input type="hidden" name="login"' >< res &&
    'Username <input name="username"' >< res &&
    ">PHP Support Tickets v" >< res
  ) {
    # Try to exploit the flaw to get a syntax error.
    postdata = string(
      "login=login&",
      "page=login&",
      "username='", SCRIPT_NAME, "&",
      "password=nessus&",
      "form=Log+In"
    );
    r = http_send_recv3(method: "POST", item: dir + "/index.php", port: port,
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail: 1, 
      data: postdata);
    res = strcat(r[0], r[1], '\r\n', r[2]);

    # There's a problem if we get a syntax error involving our script name.
    if (
      "an error in your SQL syntax" >< res &&
      string("departments.ID AND username = ''", SCRIPT_NAME) >< res
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}

