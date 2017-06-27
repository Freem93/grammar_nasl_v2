#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25352);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2007-3062");
  script_bugtraq_id(24256);
  script_osvdb_id(36829);

  script_name(english:"HP System Management Homepage < 2.1.2 Unspecified XSS");
  script_summary(english:"Checks version of HP SMH");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is susceptible to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The version of HP System Management Homepage installed on the remote
host fails to sanitize user input to unspecified parameters and
scripts before using it to generate dynamic HTML.  A remote attacker
may be able to exploit these issues to cause arbitrary HTML and script
code to be executed by a user's browser in the context of the affected
website.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/12545");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 2.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:2381, embedded:TRUE);


install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir = install['dir'];
version = install['ver'];
prod = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");
if (version == UNKNOWN_VER)
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '2.1.2';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, prod+" "+version+" is listening on port "+port+" and is not affected.");
