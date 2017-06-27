#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72730);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/03 16:44:27 $");

  script_name(english:"McAfee ePolicy Orchestrator Unsupported Version Detection");
  script_summary(english:"Checks if an ePolicy Orchestrator version is unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a security
management application.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of McAfee ePolicy
Orchestrator (ePO) on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB59938");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of McAfee ePolicy Orchestrator (ePO) that is
currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("installed_sw/McAfee ePO");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "McAfee ePolicy Orchestrator";
kb_app_name = "McAfee ePO";

install = get_single_install(app_name:kb_app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
install_path = install['path'];

eol_versions =
  make_array(
    "^4\.0\.", make_array(
      'eol_date', 'September 30 2011',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB69534'
      ),
    "^4\.5\.", make_array(
      'eol_date', 'December 31, 2013',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB76892'
      ),
    "^5\.0\.", make_array(
      'eol_date', 'December 31, 2014',
      'kb', 'http://www.mcafee.com/us/support/support-eol-software-utilities.aspx'
      ),
    "^4\.6\.", make_array(
      'eol_date', 'December 31, 2015',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB84436'
      )
    );

port = get_kb_item("SMB/transport");
if (!port) port = 445;

foreach eol (keys(eol_versions))
{
  if (version =~ eol)
  {

    register_unsupported_product(product_name:app_name,
                                 cpe_base:"mcafee:epolicy_orchestrator", version:version);

    if (report_verbosity > 0)
    {
      report =
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  End of life date  : ' + eol_versions[eol]['eol_date'] +
      '\n  EOL announcement  : ' + eol_versions[eol]['kb'] +
      '\n';
      security_hole(extra:report, port:port);
    }
    else security_hole(port);
    exit(0);
  }
}

# If no unsupported install found, then exit.
audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);
