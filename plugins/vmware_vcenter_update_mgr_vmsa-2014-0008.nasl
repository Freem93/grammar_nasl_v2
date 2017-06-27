#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77727);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0429",
    "CVE-2014-0432",
    "CVE-2014-0446",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0456",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-1876",
    "CVE-2014-2397",
    "CVE-2014-2401",
    "CVE-2014-2402",
    "CVE-2014-2403",
    "CVE-2014-2409",
    "CVE-2014-2412",
    "CVE-2014-2413",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428"
  );
  script_bugtraq_id(
    63676,
    64493,
    65568,
    66856,
    66866,
    66870,
    66873,
    66877,
    66879,
    66881,
    66883,
    66887,
    66891,
    66893,
    66894,
    66897,
    66898,
    66899,
    66902,
    66903,
    66905,
    66907,
    66909,
    66910,
    66911,
    66914,
    66915,
    66916,
    66917,
    66918,
    66919
  );
  script_osvdb_id(
    99711,
    101309,
    102808,
    105866,
    105867,
    105868,
    105869,
    105871,
    105872,
    105873,
    105874,
    105875,
    105877,
    105878,
    105879,
    105880,
    105881,
    105882,
    105883,
    105884,
    105885,
    105886,
    105887,
    105889,
    105890,
    105891,
    105892,
    105895,
    105896,
    105897,
    105898
  );
  script_xref(name:"VMSA", value:"2014-0008");

  script_name(english:"VMware vCenter Update Manager Multiple Java Vulnerabilities (VMSA-2014-0008)");
  script_summary(english:"Checks the version of Update Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an update manager installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Update Manager installed on the remote
Windows host is 5.5 prior to Update 2. It is, therefore, affected by
multiple vulnerabilities related to the bundled version of Oracle JRE
prior to 1.7.0_55.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0008.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000260.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to vCenter Update Manager 5.5 Update 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (version =~ "^5\.5\." && int(build) < 2061929)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : 5.5.0 build 2061929' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version + ' build ' + build, path);
