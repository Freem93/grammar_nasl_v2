#
# (C) Tenable Network Security, Inc.
#
# The text of this plugin is (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(59447);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/23 16:43:01 $");

  script_cve_id("CVE-2012-2448", "CVE-2012-2449", "CVE-2012-2450");
  script_osvdb_id(81693, 81694, 81695);
  script_xref(name:"VMSA", value:"2012-0009");

  script_name(english:"VMSA-2012-0009 : ESXi and ESX patches address critical security issues (uncredentialed check)");
  script_summary(english:"Checks ESX/ESXi version and build number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote VMware ESX/ESXi host is affected by multiple security
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote VMware ESX/ESXi host is affected by the following security
vulnerabilities :

  - ESX NFS traffic parsing vulnerability:
    Due to a flaw in the handling of NFS traffic, it is
    possible to overwrite memory. This vulnerability may
    allow a user with access to the network to execute code
    on the ESXi/ESX host without authentication. The issue
    is not present in cases where there is no NFS traffic.
    (CVE-2012-2448)

  - VMware floppy device out-of-bounds memory write:
    Due to a flaw in the virtual floppy configuration it is
    possible to perform an out-of-bounds memory write. This
    vulnerability may allow a guest user to crash the VMX
    process or potentially execute code on the host. As a
    workaround, remove the virtual floppy drive from the
    list of virtual IO devices. The VMware hardening guides
    recommend removing unused virtual IO devices in general.
    Additionally, do not allow untrusted root users in your
    virtual machines. Root or Administrator level
    permissions are required to exploit this issue.
    (CVE-2012-2449)

  - VMware SCSI device unchecked memory write:
    Due to a flaw in the SCSI device registration it is
    possible to perform an unchecked write into memory.
    This vulnerability may allow a guest user to crash the
    VMX process or potentially execute code on the host. As
    a workaround, remove the virtual SCSI controller from
    the list of virtual IO devices. The VMware hardening
    guides recommend removing unused virtual IO devices in
    general. Additionally, do not allow untrusted root users
    access to your virtual machines. Root or Administrator
    level permissions are required to exploit this issue.
    (CVE-2012-2450)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2012-0009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000175.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the missing patches."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include('audit.inc');
include("global_settings.inc");
include('misc_func.inc');

# build number of the patched system
fix = make_array(
  "ESXi 5.0", 702118,
  "ESXi 4.1", 702113,
  "ESXi 4.0", 702116,
  "ESXi 3.5.0", 702112, # also fixes CVE-2012-1516
  "ESX 4.1",  702113,
  "ESX 4.0",  702116,
  "ESX 3.5.0",  702112);# also fixes CVE-2012-1516

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

# extract build number
match = eregmatch(pattern:'^VMware ESXi?.*build-([0-9]+)$', string: rel);
if(isnull(match)) exit(1, 'Cannot determine ESX/ESXi build number.');

build = match[1];

if(build < fix[ver])
{
  if (report_verbosity > 0)
  {
    if ("ESXi" >< rel)
    {
      line1 = "ESXi version";
      line2 = "ESXi release";
    }
    else
    {
      line1 = "ESX version ";
      line2 = "ESX release ";
    }

    report = '\n  ' + line1 + '      : ' + ver +
             '\n  ' + line2 + '      : ' + rel +
             '\n  Installed build   : ' + build +
             '\n  Fixed build       : ' + fix[ver] +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
