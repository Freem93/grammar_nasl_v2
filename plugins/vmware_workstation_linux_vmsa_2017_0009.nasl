#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100417);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/25 16:06:46 $");

  script_cve_id("CVE-2017-4915");
  script_bugtraq_id(98566);
  script_osvdb_id(157867);
  script_xref(name:"VMSA", value:"2017-0009");
  script_xref(name:"IAVA", value:"2017-A-0160");

  script_name(english:"VMware Workstation 12.x < 12.5.6 Insecure Library Loading Privilege Escalation (VMSA-2017-0009) (Linux)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Linux host is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Linux host
is 12.x prior to 12.5.6. It is, therefore, affected by a privilege
escalation vulnerability in the ALSA sound driver due to insecurely
loading shared libraries via the '.asoundrc' configuration file. A
local attacker can exploit this, by loading specially crafted
libraries, to gain root privileges on the host.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2017-0009.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 12.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("Host/VMware Workstation/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");

fix = '';
if (version =~ "^12\.") fix = '12.5.6';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
