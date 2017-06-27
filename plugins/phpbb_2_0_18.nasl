#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20379);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_cve_id("CVE-2005-4357", "CVE-2005-4358");
  script_bugtraq_id(16088);
  script_osvdb_id(21803, 21804);

  script_name(english:"phpBB < 2.0.19 Multiple XSS");
  script_summary(english:"Checks for multiple cross-site scripting flaws in phpBB <= 2.0.18");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several flaws.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote version of this software
is vulnerable to JavaScript injection issues using 'url' bbcode tags
and, if HTML tags are enabled, HTML more generally. This may allow an
attacker to inject hostile JavaScript into the forum system to steal
cookie credentials or misrepresent site content. When the form is
submitted, the malicious JavaScript will be incorporated into
dynamically-generated content.

In addition, an attacker may be able to learn the full path of the
install by calling 'admin/admin_disallow.php' provided PHP's
'register_globals' and 'display_errors' are both enabled.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/852");
  script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=352966");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpBB version 2.0.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpbb_group:phpbb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport", "www/phpBB");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);


matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	version = matches[1];
	if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[0-8])[^0-9])", string:version)) {
	   security_warning(port);
	   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	   exit(0);
	}
}
