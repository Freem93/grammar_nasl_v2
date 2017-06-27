#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18298);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1712", "CVE-2005-1713");
  script_bugtraq_id(13669);
  script_osvdb_id(16659, 16660, 16661);

  script_name(english:"Serendipity < 0.8.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Serendipity installed on the
remote host is affected by multiple vulnerabilities :

  - Unauthorized File Upload Vulnerability
    There is a vulnerability that may allow editors to 
    upload arbitrary media files when they otherwise would 
    not be allowed to do so.

  - Multiple Cross-Site Scripting Vulnerabilities
    The 'templedropdown' and 'shutbox' plugins could allow
    attackers to inject arbitrary HTML and script code into
    users' browsers, thereby facilitating cross-site
    scriptings attacks." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=328092" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity version 0.8.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/17");

 script_cvs_date("$Date: 2015/02/13 21:07:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:s9y:serendipity");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Serendipity < 0.8.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/serendipity");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: version 0.8.1 fixes the flaw.
  if (ver =~ "^0\.([0-7]|8([^0-9.]|$))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
