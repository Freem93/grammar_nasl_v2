#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66541);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/22 15:11:02 $");

  script_bugtraq_id(58817);
  script_osvdb_id(91812);
  script_xref(name:"EDB-ID", value:"24937");

  script_name(english:"HP System Management Homepage < 7.2.0.14 iprange Parameter Code Execution");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is a version
prior to 7.2.0.14 and is, therefore, reportedly affected by a code
execution vulnerability related to the 'iprange' parameter in requests
made to '/proxy/DataValidation'

Note that successful exploitation requires that anonymous access is
enabled."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareDescription.jsp?swItem=MTX-d5ca6742524148a7bc57859fc3&lang=en&cc=us&mode=5&
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2db75ce"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to HP System Management Homepage 7.2.0.14 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP System Management Anonymous Access Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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


port    = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER)
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.2.0.14';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
