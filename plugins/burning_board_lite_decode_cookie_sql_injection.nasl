#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23733);
  script_version ("$Revision: 1.17 $");
script_cvs_date("$Date: 2017/05/02 23:36:52 $");

  script_cve_id("CVE-2006-6237");
  script_osvdb_id(30681);
  script_xref(name:"EDB-ID", value:"2841");

  script_name(english:"WoltLab Burning Board Lite thread.php decode_cookie Function threadvisit Cookie Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerability in Burning Board Lite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of Burning Board Lite fails to sanitize user-
supplied cookie input before using it in the 'decode_cookie()'
function in a database query.  Regardless of PHP settings, an
unauthenticated attacker may be able to leverage this issue to uncover
sensitive information (such as password hashes), modify existing data,
or launch attacks against the underlying database." );
 # https://web.archive.org/web/20061229210354/http://retrogod.altervista.org/wbblite_102_sql_mqg_bypass.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ea20cac");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/24");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("burning_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);


# Test any installs.
install = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # First we need a thread id.
  idx = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  pat = '<a href="thread\\.php\\?.*threadid=([0-9]+)';
  matches = egrep(pattern:pat, string: idx);
  tid = NULL;
  if (matches) 
  {
    foreach match (split(matches)) 
    {
      match = chomp(match);
      thread = eregmatch(pattern:pat, string:match);
      if (!isnull(thread)) {
        tid = thread[1];
        break;
      }
    }
  }

  # If we have a thread id.
  if (isnull(tid))
  {
    debug_print("couldn't find a thread id to use!", level:0);
  }
  else 
  {
    # Try to exploit the flaw to generate a SQL error.
    set_http_cookie( name: "threadvisit", 
    		     value: strcat("1,999999999999999'", SCRIPT_NAME));
    r = http_send_recv3(port:port, method: 'POST', version: 11,
 item: strcat(dir, "/thread.php?threadid=", tid), data: "goto=firstnew",
 exit_on_fail: 1,
 content_type: "application/x-www-form-urlencoded");

    # There's a problem if we see a database error with our script name.
    res = r[1]+r[2];
    if (
      "SQL-DATABASE ERROR" >< res &&
      string("posttime>'999999999999999'", SCRIPT_NAME) >< res
    ) {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
}
