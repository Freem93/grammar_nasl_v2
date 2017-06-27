#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93403);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2015-8482");
  script_bugtraq_id(78068);
  script_osvdb_id(130729);
  script_xref(name:"IAVA", value:"2016-A-0227");

  script_name(english:"Blue Coat Unified Agent < 4.6.2 Configuration File Manipulation Detection Failure");
  script_summary(english:"Checks the version of Unified Agent.");

  script_set_attribute(attribute:"synopsis", value:
"A security and acceleration application installed on the remote
Windows host is affected by a failure to detect manipulation of a
configuration file.");
  script_set_attribute(attribute:"description", value:
"The version of Blue Coat Unified Agent installed on the remote Windows
host is prior to 4.6.2. It is, therefore, affected by a flaw due to a
failure to detect when a configuration file has been changed by an
administrator when running in local enforcement mode. A local attacker
can exploit this to unblock categories or disable Unified Agent
entirely.

Note that Unified Agents running in cloud mode are not affected by the
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa102");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Blue Coat Unified Agent version 4.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bluecoat:unified_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("bluecoat_unified_agent_installed.nbin");
  script_require_keys("installed_sw/Blue Coat Systems Unified Agent");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Blue Coat Systems Unified Agent';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

fix = '4.6.2';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version);
