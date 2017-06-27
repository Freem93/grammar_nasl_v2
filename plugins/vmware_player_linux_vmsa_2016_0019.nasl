#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95287);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/20 15:44:33 $");

  script_cve_id("CVE-2016-7461");
  script_bugtraq_id(94280);
  script_osvdb_id(147086);
  script_xref(name:"VMSA", value:"2016-0019");

  script_name(english:"VMware Player 12.x < 12.5.2 Drag-and-Drop Feature Arbitrary Code Execution (VMSA-2016-0019) (Linux)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Linux host is
affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote Linux host is
12.x prior to 12.5.2. It is, therefore, affected by an arbitrary code
execution vulnerability in the drag-and-drop feature due to an
out-of-bounds memory access error. An attacker within the guest can
exploit this to execute arbitrary code on the host system.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0019.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player version 12.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("vmware_player_linux_installed.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("Host/VMware Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Player/Version");

fix = '';
if (version =~ "^12\.") fix = '12.5.2';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Player", version);
