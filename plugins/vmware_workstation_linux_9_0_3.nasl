#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71054);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/11/18 21:03:58 $");

  script_cve_id("CVE-2013-5972", "CVE-2013-3519");
  script_bugtraq_id(63739, 64075);
  script_osvdb_id(99788, 100514);
  script_xref(name:"VMSA", value:"2013-0013");
  script_xref(name:"VMSA", value:"2013-0014");

  script_name(english:"VMware Workstation 9.x < 9.0.3 Multiple Privilege Escalation Vulnerabilities (VMSA-2013-0013 / VMSA-2013-0014)");
  script_summary(english:"Checks VMware Workstation version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software with known, local privilege
escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of VMware Workstation 9.x is prior to 9.0.3. It
is, therefore, affected by multiple local privilege escalation
vulnerabilities :

  - An issue exists in the handling of shared libraries
    that could allow a local, malicious user to escalate
    privileges on Linux hosts. (CVE-2013-5972 /
    VMSA-2013-0013)

  - An issue exists in the handling of the LGTOSYNC.SYS
    driver on Windows hosts that could allow a local,
    malicious user to escalate privileges on 32-bit Guest
    Operating Systems running Windows XP. Note that by
    exploiting this issue, a local attacker could elevate
    his privileges only on the Guest Operating System and
    not on the host. (CVE-2013-3519 / VMSA-2013-0014)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0013.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0014.html");
  script_set_attribute(attribute:"solution", value:"Update to VMware Workstation 9.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");
fixed = '9.0.3';

# 9.x < 9.0.3
if (
  ver_compare(ver:version, fix:'9.0.0', strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
