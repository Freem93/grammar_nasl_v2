#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:201. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78617);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/27 10:47:56 $");

  script_cve_id("CVE-2014-3122", "CVE-2014-3181", "CVE-2014-3182", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3534", "CVE-2014-3601", "CVE-2014-5077", "CVE-2014-5206", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-7975");
  script_bugtraq_id(67162, 68881, 68940, 69214, 69396, 69428, 69489, 69763, 69768, 69770, 69779, 69781, 69799, 70314);
  script_xref(name:"MDVSA", value:"2014:201");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2014:201)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in the Linux
kernel :

The try_to_unmap_cluster function in mm/rmap.c in the Linux kernel
before 3.14.3 does not properly consider which pages must be locked,
which allows local users to cause a denial of service (system crash)
by triggering a memory-usage pattern that requires removal of
page-table mappings (CVE-2014-3122).

Multiple stack-based buffer overflows in the magicmouse_raw_event
function in drivers/hid/hid-magicmouse.c in the Magic Mouse HID driver
in the Linux kernel through 3.16.3 allow physically proximate
attackers to cause a denial of service (system crash) or possibly
execute arbitrary code via a crafted device that provides a large
amount of (1) EHCI or (2) XHCI data associated with an event
(CVE-2014-3181).

Array index error in the logi_dj_raw_event function in
drivers/hid/hid-logitech-dj.c in the Linux kernel before 3.16.2 allows
physically proximate attackers to execute arbitrary code or cause a
denial of service (invalid kfree) via a crafted device that provides a
malformed REPORT_TYPE_NOTIF_DEVICE_UNPAIRED value (CVE-2014-3182).

The report_fixup functions in the HID subsystem in the Linux kernel
before 3.16.2 might allow physically proximate attackers to cause a
denial of service (out-of-bounds write) via a crafted device that
provides a small report descriptor, related to (1)
drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3)
drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c, (5)
drivers/hid/hid-petalynx.c, and (6) drivers/hid/hid-sunplus.c
(CVE-2014-3184).

Multiple buffer overflows in the command_port_read_callback function
in drivers/usb/serial/whiteheat.c in the Whiteheat USB Serial Driver
in the Linux kernel before 3.16.2 allow physically proximate attackers
to execute arbitrary code or cause a denial of service (memory
corruption and system crash) via a crafted device that provides a
large amount of (1) EHCI or (2) XHCI data associated with a bulk
response (CVE-2014-3185).

Buffer overflow in the picolcd_raw_event function in
devices/hid/hid-picolcd_core.c in the PicoLCD HID device driver in the
Linux kernel through 3.16.3, as used in Android on Nexus 7 devices,
allows physically proximate attackers to cause a denial of service
(system crash) or possibly execute arbitrary code via a crafted device
that sends a large report (CVE-2014-3186).

arch/s390/kernel/ptrace.c in the Linux kernel before 3.15.8 on the
s390 platform does not properly restrict address-space control
operations in PTRACE_POKEUSR_AREA requests, which allows local users
to obtain read and write access to kernel memory locations, and
consequently gain privileges, via a crafted application that makes a
ptrace system call (CVE-2014-3534).

The kvm_iommu_map_pages function in virt/kvm/iommu.c in the Linux
kernel through 3.16.1 miscalculates the number of pages during the
handling of a mapping failure, which allows guest OS users to (1)
cause a denial of service (host OS memory corruption) or possibly have
unspecified other impact by triggering a large gfn value or (2) cause
a denial of service (host OS memory consumption) by triggering a small
gfn value that leads to permanently pinned pages (CVE-2014-3601).

The sctp_assoc_update function in net/sctp/associola.c in the Linux
kernel through 3.15.8, when SCTP authentication is enabled, allows
remote attackers to cause a denial of service (NULL pointer
dereference and OOPS) by starting to establish an association between
two endpoints immediately after an exchange of INIT and INIT ACK
chunks to establish an earlier association between these endpoints in
the opposite direction (CVE-2014-5077).

The do_remount function in fs/namespace.c in the Linux kernel through
3.16.1 does not maintain the MNT_LOCK_READONLY bit across a remount of
a bind mount, which allows local users to bypass an intended read-only
restriction and defeat certain sandbox protection mechanisms via a
mount -o remount command within a user namespace (CVE-2014-5206).

Stack consumption vulnerability in the parse_rock_ridge_inode_internal
function in fs/isofs/rock.c in the Linux kernel through 3.16.1 allows
local users to cause a denial of service (uncontrolled recursion, and
system crash or reboot) via a crafted iso9660 image with a CL entry
referring to a directory entry that has a CL entry (CVE-2014-5471).

The parse_rock_ridge_inode_internal function in fs/isofs/rock.c in the
Linux kernel through 3.16.1 allows local users to cause a denial of
service (unkillable mount process) via a crafted iso9660 image with a
self-referential CL entry (CVE-2014-5472).

The __udf_read_inode function in fs/udf/inode.c in the Linux kernel
through 3.16.3 does not restrict the amount of ICB indirection, which
allows physically proximate attackers to cause a denial of service
(infinite loop or stack consumption) via a UDF filesystem with a
crafted inode (CVE-2014-6410).

The do_umount function in fs/namespace.c in the Linux kernel through
3.17 does not require the CAP_SYS_ADMIN capability for do_remount_sb
calls that change the root filesystem to read-only, which allows local
users to cause a denial of service (loss of writability) by making
certain unshare system calls, clearing the / MNT_LOCKED flag, and
making an MNT_FORCE umount system call (CVE-2014-7975).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.104-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.104-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.104-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.104-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.104-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.104-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.104-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.104-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.104-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
