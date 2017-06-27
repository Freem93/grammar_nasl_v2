#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59730);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/11/18 03:32:48 $");

  script_cve_id("CVE-2012-3288", "CVE-2012-3289");
  script_bugtraq_id(53996);
  script_osvdb_id(82979, 82980);
  script_xref(name:"VMSA", value:"2012-0011");

  script_name(english:"VMware Workstation Multiple Vulnerabilities (VMSA-2012-0011)");
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
earlier than 7.1.6, or 8.0.x earlier than 8.0.4 and is, therefore,
potentially affected by the following vulnerabilities :

  - A memory corruption error exists related to the
    handling of 'Checkpoint' files that can allow arbitrary
    code execution. (CVE-2012-3288)

  - An error exists related to handling traffic from
    remote physical devices, e.g. CD-ROM or mouse that
    can cause the virtual machine to cash. Note that this
    issue only affects the 8.x branch. (CVE-2012-3289)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0011.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4d01774");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87a43741");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation 7.1.6 / 8.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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
  fix = '8.0.4';
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
