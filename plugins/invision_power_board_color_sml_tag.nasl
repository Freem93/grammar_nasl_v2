#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17202);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2005-0477");
  script_bugtraq_id(12607);
  script_osvdb_id(14004, 14005);

  script_name(english:"Invision Power Board COLOR SML Tag XSS");
  script_summary(english:"Detect Invision Power Board COLOR SML Tag Script Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"According to the version number in its banner, the installation of
Invision Power Board on the remote host reportedly does not
sufficiently sanitize the 'COLOR' SML tag. A remote attacker may
exploit this vulnerability by adding a specially crafted 'COLOR' tag
with arbitrary JavaScript to any signature or post on an Invision
board. That JavaScript will later be executed in the context of users
browsing that forum, which may enable an attacker to steal cookies or
misrepresent site content.

In addition, it has been reported that an attacker can inject
arbitrary script into a signature file. However, Nessus has not tested
for this issue.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Feb/326");
  script_set_attribute(attribute:"see_also", value:"http://forums.invisionpower.com/index.php?showtopic=160633");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:invisionpower:invision_power_board");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/invision_power_board", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: don't run unless we're being paranoid since the solution is a patch.
if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(1\.([12]\.|3\.[01])|2\.0\.[0-3])")
  {
   security_note(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
