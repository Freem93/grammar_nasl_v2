#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97990);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2017-4901");
  script_bugtraq_id(96881);
  script_osvdb_id(153609);
  script_xref(name:"VMSA", value:"2017-0005");

  script_name(english:"VMware Player 12.x < 12.5.4 Drag-and-Drop Feature Guest-to-Host Code Execution (VMSA-2017-0005)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by a guest-to-host arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote Windows host
is 12.x prior to 12.5.4. It is, therefore, affected by a guest-to-host
arbitrary code execution vulnerability in the drag-and-drop (DND)
functionality due to an out-of-bounds memory access error. An attacker
within a guest can exploit this issue to execute arbitrary code on the
host system.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player version 12.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Player");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

install = get_single_install(app_name:"VMware Player", exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '';
if (version =~ "^12\.") fix = '12.5.4';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
