#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20992);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-1040");
  script_bugtraq_id(16919);
  script_osvdb_id(23614);

  script_name(english:"vBulletin Email Field XSS");
  script_summary(english:"Checks version number of vBulletin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of vBulletin installed on the
remote host does not properly sanitize user-supplied-input to the
email field in the 'profile.php' script.  Using a specially crafted
email address in his profile, an authenticated attacker can leverage
this issue to inject arbitrary HTML and script code into the browsers
of users who view the attacker's profile." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426537/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.vbulletin.com/forum/showthread.php?t=176170" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.5.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/02");

 script_cvs_date("$Date: 2015/02/13 21:07:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:jelsoft:vbulletin");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("vbulletin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/vBulletin");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-2]\.|3\.([0-4]\.|5\.[0-3]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
