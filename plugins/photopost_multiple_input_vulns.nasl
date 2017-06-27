#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17649);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-0928", "CVE-2005-0929");
  script_bugtraq_id(12920);
  script_osvdb_id(15096, 15097, 15098, 15099, 15100);

  script_name(english:"PhotoPost < 5.1 Multiple Input Validation Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of PhotoPost PHP installed on the remote host is prone to
multiple input validation vulnerabilities:

  o Multiple SQL Injection Vulnerabilities
    The application fails to properly sanitize user-input via
    the 'sl' parameter of the 'showmembers.php' script, and 
    the 'photo' parameter of the 'showphoto.php' script. An 
    attacker can exploit these flaws to manipulate SQL 
    queries, possibly destroying or revealing sensitive data.

  o Multiple Cross-Site Scripting Vulnerabilities
    The application fails to properly sanitize user-input via
    the 'photo' parameter of the 'slideshow.php' script, the
    'cat', 'password', 'si', 'ppuser', and 'sort' parameters
    of the 'showgallery.php' script, and the 'ppuser', 'sort', 
    and 'si' parameters of the 'showmembers.php' script.
    An attacker can exploit these flaws to inject arbitrary 
    HTML or code script in a user's browser in the context of 
    the affected website, resulting in theft of 
    authentication data or other such attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/483" );
 script_set_attribute(attribute:"solution", value:
"The issues are reportedly fixed by upgrading to PhotoPost PHP version
5.1." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/28");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php_pro");
 script_end_attributes();

  script_summary(english:"Checks for multiple input validation vulnerabilities in PhotoPost PHP");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("photopost_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/photopost");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try some SQL injection exploits.
  exploits = make_list(
    "/showmembers.php?sl='nessus",
    "/showphoto.php?photo='nessus"
  );
  foreach exploit (exploits) {
    r = http_send_recv3(method:"GET",item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];
    if (
      egrep(string:res, pattern:"argument is not a valid MySQL result resource") ||
      egrep(string:res, pattern:">MySQL error reported!<.+>Script:")
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
