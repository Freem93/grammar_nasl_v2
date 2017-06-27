#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29596);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2012/05/17 11:27:19 $");

  script_name(english:"SuSE 10 Security Update : Xen (ZYPP Patch Number 2155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes both bug fixes and security fixes for Xen.

A summary of the fixes appears below: 151105 - Fix various 'leaks' of
loopback devices w/ domUloader 162865 - Re-send all page tables when
migrating to avoid oops 167145 - Add status messages during file
backed disk creation 176369 - YaST2-VM incorrectly reports 'Not enough
free memory' if not on xen 176449 - Backport credit scheduler, for
better performance 176717 - [XEN-HVM]Failed to install win2k hvm guest
184175 - System rebooted during Virtual Machine (guest OS)
installation 184727 - Error starting VM from YaST with maximum memory
size (partial fix) 184727 - fix calculation of largest memory size of
VM 185557 - update xendomains to wait for shutdown to complete 185557
- 'xm shutdown -w' must wait for loopback devices to be destroyed
186930 - Logical volumes (LVM) are not displayed when adding block
device 189765 - using an LV as VM block device gives bogus warning
189815 - Increase balloon timeout value, for large memory machines
190170 - Do not open migration port by default 190869 - Default to
non-sync loopback; give choice to user per-disk 191627 - Fix startup
errors in disk created by mk-xen-rescue-img 191853 - Fix overflows in
lomount, for virtual disks > 2 GB 192150 - Xen issue with privileged
instruction 192308 - disable alignment checks in kernel mode (fixes
eDir/NICI) 193854 - Add arch-invarient qemu-dm link, so config file is
portable 193854 - lib vs lib64 is hard-coded into VM definition file
194389 - YaST2 xen Module Bug in X Detection 196169 - Make domUloader
honor the dry-run flag 197777 - do not default to 'bridge=xenbr0' in
the VM config file 201349 - xendomains did not actually save domains
203731 - Allow VM's RAM to be enlarged after starting VM (fix maxmem
setting) 204153 - default to using vif0/xenbr0 if vifnum is not set or
no default route 206312 - Fix TEST_UNIT_READY to work with ISO images;
fixes Windows BSOD. 209743 - Do not delay interrupt injection if the
guest IF_FLAG disallows intr xxxxxx - changeset 9763: grant table fix
xxxxxx - do not expose MCE/MCA bits in CPUID on SVM xxxxxx - quiet
debug messages in SVM xxxxxx - update block-nbd so that it works again"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2155.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-devel-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-doc-html-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-doc-pdf-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-doc-ps-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-libs-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-tools-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"xen-tools-ioemu-3.0.2_09763-0.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"yast2-vm-2.13.62-4.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"xen-libs-32bit-3.0.2_09763-0.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
