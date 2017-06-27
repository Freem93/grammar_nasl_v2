#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77156);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/04 21:07:50 $");

  script_bugtraq_id(67622);
  script_osvdb_id(107352);

  script_name(english:"Atlassian Bamboo < 5.4.3 / 5.5.1 / 5.6.0 XWork Library ClassLoader Manipulation Remote Code Execution");
  script_summary(english:"Checks the version of Atlassian Bamboo.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian Bamboo running on the remote host is version 5.4.x prior to
5.4.3 or 5.5.x prior to 5.5.1. It is, therefore, affected by an
unspecified flaw in the XWork library. An unauthenticated, remote
attacker can exploit this, via manipulation of the ClassLoader, to
execute arbitrary Java code. Note that the attacker must be able to
access the Bamboo web interface, and if anonymous access is enabled, a
valid user account is not needed to exploit the vulnerability.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/display/BAMBOO/Bamboo+Security+Advisory+2014-05-21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb582750");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BAM-14571?src=confmacro");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Bamboo version 5.4.3 / 5.5.1 / 5.6.0 or later.
Alternatively, apply the patches provided by the vendor. ");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bamboo");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("bamboo_detect.nbin");
  script_require_ports("Services/www", 8085);
  script_require_keys("installed_sw/bamboo", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Bamboo";
app_name = tolower(app);

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8085);

install = get_single_install(
  app_name : app_name,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir     = install['path'];
version = install['version'];
build = install['build'];

install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Granularity Check for 5.4.x since there is a 5.4 version rather than 5.4.0
if (version =~ '^5(\\.4)?$')
{
  gran = FALSE;

  if ( build != UNKNOWN_VER)
  {
    if (build == "4206")
    {
      gran = TRUE;
      version = '5.4.0';
    }
  }
  if (!gran)
    audit(AUDIT_VER_NOT_GRANULAR, app, port, version);
}

vuln = FALSE;

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 5) ||
  (ver[0] == 5 && ver[1] < 4)
)
{
  vuln = TRUE;
  fix_ver = '5.4.3 / 5.5.1';
}
# 5.4.x < 5.4.3
else if (version =~ '^5\\.4')
{
  fix_ver = '5.4.3';
  if (ver[0] == 5 && ver[1] == 4 && ver[2] < 3)
    vuln = TRUE;
}
# 5.5.x < 5.5.1
else if (version =~ '^5\\.5')
{
  fix_ver = '5.5.1';
  if (ver[0] == 5 && ver[1] == 5 && ver[2] < 1)
    vuln = TRUE;
}

if (vuln)
{
  # Unmangle version 5.4 for display in the report
  if (version == '5.4.0') version = '5.4';
  if (report_verbosity > 0)
  {
    report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_ver + ' / 5.6.0 or later\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
