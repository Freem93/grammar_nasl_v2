#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73921);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/19 20:54:54 $");

  script_cve_id("CVE-2014-0646");
  script_bugtraq_id(67172);
  script_osvdb_id(106534);
  script_xref(name:"IAVB", value:"2014-B-0052");

  script_name(english:"EMC RSA Access Manager Information Disclosure (ESA-2014-029)");
  script_summary(english:"Checks EMC RSA Access Manager version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of EMC RSA Access Manager
that is reportedly affected by an information disclosure vulnerability
if the logging level is set to INFO. This could result in passwords
being logged in plaintext.");
  # http://seclists.org/bugtraq/2014/Apr/att-190/ESA-2014-029.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9630a1b5");
  script_set_attribute(attribute:"solution", value:"Refer to vendor advisory ESA-2014-029 for patch information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_access_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("emc_rsa_access_manager_installed.nbin");
  script_require_keys("installed_sw/EMC RSA Access Manager");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "EMC RSA Access Manager";
get_install_count(app_name:app_name, exit_if_zero:TRUE);
fix = NULL;

# Only 1 install of the server is possible.
install = get_installs(app_name:app_name);
if (install[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, app_name);
install = install[1][0];

version = install['version'];
path = install['path'];

# Determine fix if affected branch.
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
else if (version =~ "^6\.1\.3(\.|$)") fix = "6.1.3.39";
else if (version =~ "^6\.1\.4(\.|$)") fix = "6.1.4.22";
else if (version =~ "^6\.2(\.0|$)") fix = "6.2.0.11";
else if (version =~ "^6\.2\.1(\.|$)") fix = "6.2.1.03";

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
