#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79864);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/28 19:00:58 $");

  script_cve_id(
    "CVE-2014-2483",
    "CVE-2014-2490",
    "CVE-2014-4208",
    "CVE-2014-4209",
    "CVE-2014-4216",
    "CVE-2014-4218",
    "CVE-2014-4219",
    "CVE-2014-4220",
    "CVE-2014-4221",
    "CVE-2014-4223",
    "CVE-2014-4227",
    "CVE-2014-4244",
    "CVE-2014-4247",
    "CVE-2014-4252",
    "CVE-2014-4262",
    "CVE-2014-4263",
    "CVE-2014-4264",
    "CVE-2014-4265",
    "CVE-2014-4266",
    "CVE-2014-4268"
  );
  script_bugtraq_id(
    68562,
    68571,
    68576,
    68580,
    68583,
    68590,
    68596,
    68599,
    68603,
    68608,
    68612,
    68615,
    68620,
    68624,
    68626,
    68632,
    68636,
    68639,
    68642,
    68645
  );
  script_osvdb_id(
    109124,
    109125,
    109126,
    109127,
    109128,
    109129,
    109130,
    109131,
    109132,
    109133,
    109134,
    109135,
    109136,
    109137,
    109138,
    109139,
    109140,
    109141,
    109142,
    109143
  );

  script_xref(name:"VMSA", value:"2014-0012");

  script_name(english:"VMware vCenter Update Manager Multiple Java Vulnerabilities (VMSA-2014-0012)");
  script_summary(english:"Checks the version of Update Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an update manager installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Update Manager installed on the remote
Windows host is 5.1 prior to Update 3. It is, therefore, affected by
multiple vulnerabilities related to the bundled version of Oracle JRE
prior to 1.6.0_81.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0012.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000283.html");
  # https://www.vmware.com/support/vsphere5/doc/vsphere-update-manager-51u3-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fad0eeab");
  script_set_attribute(attribute:"solution", value:"Upgrade to vCenter Update Manager 5.1 Update 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_update_mgr_installed.nasl");
  script_require_keys("SMB/VMware vCenter Update Manager/Version", "SMB/VMware vCenter Update Manager/Build", "SMB/VMware vCenter Update Manager/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'VMware vCenter Update Manager';
version = get_kb_item_or_exit("SMB/" + app + "/Version");
build = get_kb_item_or_exit("SMB/" + app + "/Build");
path = get_kb_item_or_exit("SMB/" + app + "/Path");

if (version =~ "^5\.1\." && int(build) < 2303976)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : 5.1.0 build 2303976' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version + ' build ' + build, path);
