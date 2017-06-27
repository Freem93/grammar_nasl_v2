#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20861);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-0565");
  script_bugtraq_id(16495);
  script_osvdb_id(22921);

  script_name(english:"Loudblog backend_settings.php Multiple Parameter Remote File Inclusion");
  script_summary(english:"Checks for remote file include vulnerability in Loudblog's backend_settings.php");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Loudblog, a PHP application for publishing
podcasts and similar media files. 

The installed version of Loudblog fails to validate user input to the
'GLOBALS[path]' and 'language' parameters before using them in the
'loudblog/inc/backend_settings.php' script in a PHP 'include'
function.  Provide PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can exploit this flaw to run arbitrary code,
possibly taken from third-party hosts, subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/423947/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://loudblog.de/forum/viewtopic.php?id=576" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Loudblog 0.41 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/03");
 script_cvs_date("$Date: 2011/03/14 21:48:06 $");
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

port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/loudblog", "/podcast", "/podcasts", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If ...
  if (
    # there's a logo for Loudblog or...
    egrep(pattern:">Powered by <[^>]+>Loudblog<", string:res) ||
    # it hasn't been installed yet.
    ">Install Loudblog now!<" >< res
  ) {
    # Try to exploit the flaw to read '/loudblog/inc/id3/write.php',
    # which will die with an error message.
    postdata = string(
      "language=../inc/id3/write"
    );
    url = string(
      dir, "/loudblog/inc/backend_settings.php?",
      "GLOBALS[path]=../.."
    );
    w = http_send_recv3(method:"POST", port: port, item: url,
      exit_on_fail: 1,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    res = w[2];

    # There's a problem if we get a message about including getid3.php.
    if ("getid3.php MUST be included before calling" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}
