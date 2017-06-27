#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49776);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_bugtraq_id(43294);
  script_osvdb_id(68087);
  script_xref(name:"Secunia", value:"41391");

  script_name(english:"Nagios XI < 2009R1.3C grab_request_var() Multiple XSS");
  script_summary(english:"Version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has multiple cross-site scripting
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the Nagios XI installation on
the remote host has multiple cross-site scripting vulnerabilities.
The 'grab_request_var()' function doesn't properly sanitize user
input.  This affects input to multiple parameters on the
'admin/users.php' page.

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted URL, resulting in arbitrary script
code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-115/");
  # http://web.archive.org/web/20101124000600/http://assets.nagios.com/downloads/nagiosxi/CHANGES.TXT
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf01b1cf"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios XI 2009R1.3C or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/16");  
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl");
  script_require_keys("www/nagios_xi");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'nagios_xi', port:port, exit_on_fail:TRUE);
url = build_url(qs:install['dir'], port:port);

match = eregmatch(string:install['ver'], pattern:'([^ ]*)( build ([0-9]+)|$)');
if (match)
{
  ver = match[1];
  build = int(match[3]);
}
else exit(1, 'Error parsing version of Nagios XI install at '+url);

# Only attempt the regex comparisons if there's no build number to compare.
if (
  (build != 0 && build < 20100916) ||
  (build == 0 && ver =~ '^2009R(C|1$|1\\.[0-2]|1\\.3B?$)')
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    fixed_ver = '2009R1.3C build 20100916';
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + install['ver'] +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'Nagios XI version '+install['ver']+' at '+url+' is not affected.');
