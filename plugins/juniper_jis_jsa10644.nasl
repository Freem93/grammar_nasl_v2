#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77687);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2014-3811");
  script_bugtraq_id(69797);
  script_xref(name:"IAVA", value:"2014-A-0138");

  script_name(english:"Juniper Installer Service 7.4 < 7.4r6 Privilege Escalation (JSA10644)");
  script_summary(english:"Checks the Juniper Installer Service version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a software management application installed that
is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Juniper
Installer Service on the remote Windows host is version 7.4 prior to
7.4r6. It is, therefore, affected by a privilege escalation
vulnerability that allows a local user to gain administrative
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10644");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=KB29453");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=KB29453");
  script_set_attribute(attribute:"solution", value:"Upgrade to Juniper Installer Service 7.4r6 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:installer_service");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("juniper_jis_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Juniper Installer Service");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "Juniper Installer Service";

# Force windows only, this client can not be installed on MacOSX
get_kb_item_or_exit("SMB/Registry/Enumerated");
get_install_count(app_name:appname, exit_if_zero:TRUE);

install = get_single_install(app_name:appname,exit_if_unknown_ver:TRUE);
version = install['version'];
fix     = "7.4.6";
path    = install['path'];

if (ver_compare(ver:version,fix:fix,strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Install path      : ' +  path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
