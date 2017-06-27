#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83184);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/04 14:10:50 $");

  script_cve_id("CVE-2014-6593");
  script_bugtraq_id(72169);
  script_osvdb_id(117238);
  script_xref(name:"VMSA", value:"2015-0003");

  script_name(english:"VMware vSphere Update Manager Java Vulnerability (VMSA-2015-0003)");
  script_summary(english:"Checks the version of Update Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an update manager installed that is affected by
a Java Runtime Environment (JRE) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Update Manager installed on the remote
Windows host is 5.0 prior to Update 3d, 5.1 prior to Update 3a, 5.5
prior to Update 2e, or 6.0 prior to 6.0.0a. It is, therefore, affected
by a vulnerability related to the bundled version of Oracle JRE prior
to 1.7.0_76. A flaw exists in the JSSE component due to improper
ChangeCipherSpec tracking during SSL/TLS handshakes. This can be
exploited by a man-in-the-middle attacker to cause an unencrypted
connection to be established.

Note that the application was formerly named vCenter Update Manager.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0003.html");
  # https://www.vmware.com/support/vsphere5/doc/vsphere-update-manager-50u3d-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65907755");
  # https://www.vmware.com/support/vsphere5/doc/vsphere-update-manager-51u3a-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfac928a");
  # https://www.vmware.com/support/vsphere5/doc/vsphere-update-manager-55u2e-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?227f6681");
  # https://www.vmware.com/support/vsphere6/doc/vsphere-update-manager-600a-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c26cddb");
  script_set_attribute(attribute:"solution", value:
"Upgrade vSphere Update Manager to 5.0 Update 3d / 5.1 Update 3a / 5.5
Update 2e / 6.0.0a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_update_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_update_mgr_installed.nasl");
  script_require_keys("installed_sw/VMware vCenter Update Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include('install_func.inc');

app = 'VMware vCenter Update Manager';
install = get_single_install(app_name: app, exit_if_unknown_ver: TRUE);

version = install["version"];
path = install["path"];
build = install["Build"];

fix = NULL;

fix50 = 2692649;
fix51 = 2650847;
fix55 = 2595792;
fix60 = 2503190;

if (version =~ "^5\.0\." && int(build) < fix50) fix = fix50;
if (version =~ "^5\.1\." && int(build) < fix51) fix = fix51;
if (version =~ "^5\.5\." && int(build) < fix55) fix = fix55;
if (version =~ "^6\.0\." && int(build) < fix60) fix = fix60;

if (!isnull(fix))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : ' + version + ' build ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version + ' build ' + build, path);
