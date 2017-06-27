#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59092);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:53:04 $");

  script_cve_id(
    "CVE-2012-1516",
    "CVE-2012-1517",
    "CVE-2012-2449",
    "CVE-2012-2450"
  );
  script_bugtraq_id(53369);
  script_osvdb_id(81691, 81692, 81694, 81695);
  script_xref(name:"VMSA", value:"2012-0009");

  script_name(english:"VMware Workstation Multiple Vulnerabilities (VMSA-2012-0009)");
  script_summary(english:"Checks VMware Workstation version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtualization application that is affected by 
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The VMware Workstation install detected on the remote host is 7.x
earlier than 7.1.6 or 8.0.x earlier than 8.0.3 and is, therefore,
potentially affected by the following vulnerabilities :

  - Memory corruption errors exist related to the
    RPC commands handler function which could cause the
    application to crash or possibly allow an attacker to
    execute arbitrary code. Note that these errors only
    affect the 3.x branch. (CVE-2012-1516, CVE-2012-1517)

  - An error in the virtual floppy device configuration
    can allow out-of-bounds memory writes and can allow
    a guest user to crash the VMX process or potentially
    execute arbitrary code on the host. Note that root or
    administrator level privileges in the guest are required
    for successful exploitation along with the existence of
    a virtual floppy device in the guest. (CVE-2012-2449)

  - An error in the virtual SCSI device registration
    process can allow improper memory writes and can allow
    a guest user to crash the VMX process or potentially
    execute arbitrary code on the host. Note that root or
    administrator level privileges are required in the
    guest for successful exploitation along with the
    existence of a virtual SCSI device in the guest.
    (CVE-2012-2450)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0009.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000176.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4d01774");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a550479");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation 7.1.6 / 8.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");


version = get_kb_item_or_exit("VMware/Workstation/Version");

vulnerable = NULL;

# 7.x
if (version =~ '^7\\.')
{
  fix = '7.1.6';
  vulnerable = ver_compare(ver:version, fix:fix, strict:FALSE);
}

# 8.x
if (version =~ '^8\\.0')
{
  fix = '8.0.3';
  vulnerable = ver_compare(ver:version, fix:fix, strict:FALSE);
}

if (vulnerable < 0)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report += 
      '\n  Installed version : '+version+
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole();
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
