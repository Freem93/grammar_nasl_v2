#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17205);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-0258", "CVE-2005-0259"); 
  script_bugtraq_id(12618, 12621, 12623);
  script_osvdb_id(
    14038, 
    14039, 
    14040, 
    14041, 
    14042
 );
 
  script_name(english:"phpBB <= 2.0.11 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpBB version 2.0.11 or older.  Such
versions suffer from multiple vulnerabilities:

  - full path display on critical messages.
  - full path disclosure in username handling caused by a PHP 4.3.10 bug.
  - arbitrary file disclosure vulnerability in avatar handling functions.
  - arbitrary file unlink vulnerability in avatar handling functions.
  - path disclosure bug in search.php caused by a PHP 4.3.10 bug.
  - path disclosure bug in viewtopic.php caused by a PHP 4.3.10 bug.

The path disclosure vulnerabilities can be exploited by remote
attackers to reveal sensitive information about the installation that
can be used in further attacks against the target. 

To exploit the avatar handling vulnerabilities, 'Enable gallery
avatars' must be enabled on the target (by default, it is disabled)
and an attacker have a phpBB account on the target." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB 2.0.12 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/21");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/02/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

 
 summary["english"] = "Multiple vulnerabilities in phpBB version 2.0.11 and older";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

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

  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[01])([^0-9]|$))")
    security_warning(port);
}
