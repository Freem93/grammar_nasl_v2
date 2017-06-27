#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84046);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/29 16:35:33 $");

  script_name(english:"McAfee Agent Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"A system security agent running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
McAfee Agent (formerly known as McAfee Common Management Agent) on the
remote host is no longer supported. McAfee Agent is a component of the
McAfee's ePolicy Orchestrator (ePO) system security management
solution.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com/us/support/support-eol.aspx#product=mcafee_agent");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of McAfee Agent that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_detect.nasl", "mcafee_cma_installed.nbin");
  script_require_ports("Services/www", 8081, "installed_sw/McAfee Agent");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

eol_dates = make_array(
#  "^5\.0($|[^0-9])"    , "Current",
#  "^4\.8($|[^0-9])"    , "Current",
  "^4\.6($|[^0-9])"    , "2015/03/31",
  "^4\.5($|[^0-9])"    , "2014/06/30",
  "^4\.0($|[^0-9])"    , "2015/12/31",
#  "^3\.7($|[^0-9])"    , "Current",
  "^3\.6($|[^0-9])"    , "2015/12/31"
);

eol_urls  = make_array(
#  "^5\.0($|[^0-9])"    , "https://kc.mcafee.com/corporate/index?page=content&id=KBXXXXX",
#  "^4\.8($|[^0-9])"    , "https://kc.mcafee.com/corporate/index?page=content&id=KBXXXXX",
  "^4\.6($|[^0-9])"    , "https://kc.mcafee.com/corporate/index?page=content&id=KB79970",
  "^4\.5($|[^0-9])"    , "https://kc.mcafee.com/corporate/index?page=content&id=KB79969",
  "^4\.0($|[^0-9])"    , "https://kc.mcafee.com/corporate/index?page=content&id=KB85993",
#  "^3\.7($|[^0-9])"    , "https://kc.mcafee.com/corporate/index?page=content&id=KBXXXXX",
  "^3\.6($|[^0-9])"    , "https://kc.mcafee.com/corporate/index?page=content&id=KB85993"
);

appname = "McAfee Agent";

path = NULL;
ver = NULL;

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE, combined:TRUE);

ver  = install['version'];
path = install['path'];
port = install['port'];

if (!port) port = get_kb_item("SMB/transport");
if (!port) port = 445;

default_eol_url = "http://www.nessus.org/u?197eda52";
unsupported = FALSE;

foreach ver_regex (keys(eol_dates))
{
  if (ver !~ ver_regex) continue;

  eol_date = eol_dates[ver_regex];

  if (!isnull(eol_urls[ver_regex]))
    eol_url = eol_urls[ver_regex];
  else
    eol_url = default_eol_url;

  unsupported = TRUE;

  break;
}

if (unsupported)
{
  register_unsupported_product(
    product_name : appname,
    cpe_base     : "mcafee:mcafee_agent",
    version      : ver
  );

  report = '';

  if (!empty_or_null(path))
    report += '\n  Path              : ' + path;

  report +=
    '\n  Installed version : ' + ver  +
    '\n  EOL date          : ' + eol_date +
    '\n  EOL URL           : ' + eol_url  +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, ver);
