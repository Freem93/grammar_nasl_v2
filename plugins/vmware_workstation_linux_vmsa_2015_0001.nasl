#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81186);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/21 04:38:56 $");

  script_cve_id("CVE-2014-8370", "CVE-2015-1043", "CVE-2015-1044");
  script_bugtraq_id(72336, 72337, 72338);
  script_osvdb_id(117669, 117670, 117671);
  script_xref(name:"VMSA", value:"2015-0001");

  script_name(english:"VMware Workstation 10.x < 10.0.5 Multiple Vulnerabilities (VMSA-2015-0001) (Linux)");
  script_summary(english:"Checks VMware Workstation version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a virtualization application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
version 10.x prior to 10.0.5. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified flaw exists that allows a local attacker
    to escalate privileges or cause a denial of service
    via an arbitrary write to a file. (CVE-2014-8370)

  - An input validation error exists in the Host Guest File
    System (HGFS) that allows a local attacker to cause a
    denial of service of the guest operating system.
    (CVE-2015-1043)

  - An input validation error exists in the VMware
    Authorization process (vmware-authd) that allows a
    remote attacker to cause a denial of service of the host
    operating system. (CVE-2015-1044)");
  # http://lists.vmware.com/pipermail/security-announce/2015/000286.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bded33c");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0001.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation 10.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("Host/VMware Workstation/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");
fixed = '10.0.5';

# 10.x < 10.0.5
if (
  ver_compare(ver:version, fix:'10.0.0', strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
