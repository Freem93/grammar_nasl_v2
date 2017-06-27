#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18626);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2161");
  script_bugtraq_id(14151);
  script_osvdb_id(17888);

  script_name(english:"phpBB < 2.0.17 Nested BBCode URL Tags XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by a cross-
site scripting issue." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of phpBB
that fails to sanitize BBCode containing nested URL tags, which
enables attackers to cause arbitrary HTML and script code to be
executed in a user's browser within the context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/404300/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB version 2.0.17 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/06");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

  script_summary(english:"Checks for nested BBCode URL tags cross-site scripting vulnerability in phpBB <= 2.0.16");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-6])([^0-9]|$))")
  {
   security_note(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
