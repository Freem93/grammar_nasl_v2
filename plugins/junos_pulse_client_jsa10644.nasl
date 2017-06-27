#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77688);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2014-3811");
  script_bugtraq_id(69797);
  script_xref(name:"IAVA", value:"2014-A-0138");

  script_name(english:"Juniper Junos Pulse Client Privilege Escalation (JSA10644)");
  script_summary(english:"Checks the Junos Pulse Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a VPN Client installed that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Junos
Pulse Client on the remote Windows host is version 4.0 prior to 4.0r6
or a version prior to 3.1r8. It is, therefore, affected by a privilege
escalation vulnerability that allows a local attacker to gain
administrative privileges via unspecified vectors.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10644");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=KB29453");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Pulse Client 7.4r6 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_client");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("juniper_pulse_client_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Juniper Junos Pulse Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "Juniper Junos Pulse Client";

# Force windows only, this client can be installed on MacOSX
get_kb_item_or_exit("SMB/Registry/Enumerated");
get_install_count(app_name:appname, exit_if_zero:TRUE);

install = get_single_install(app_name:appname,exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

if(
  (version =~ "^4\.0\." && ver_compare(ver:version,fix:"4.0.6",strict:FALSE) < 0) ||
  ver_compare(ver:version,fix:"3.1.9",strict:FALSE) < 0 # 3.1.9 is not a fix, however 3.1.8 and below are affected
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Install path      : ' +  path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0r6 / 5.0r1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
