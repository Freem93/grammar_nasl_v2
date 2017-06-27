#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60925);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3881");

  script_name(english:"Scientific Linux Security Update : kvm on SL5.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that some structure padding and reserved fields in
certain data structures in QEMU-KVM were not initialized properly
before being copied to user-space. A privileged host user with access
to '/dev/kvm' could use this flaw to leak kernel stack memory to
user-space. (CVE-2010-3881)

This update also fixes the following bugs :

  - The 'kvm_amd' kernel module did not initialize the TSC
    (Time Stamp Counter) offset in the VMCB (Virtual Machine
    Control Block) correctly. After a vCPU (virtual CPU) has
    been created, the TSC offset in the VMCB should have a
    negative value so that the virtual machine will see TSC
    values starting at zero. However, the TSC offset was set
    to zero and therefore the virtual machine saw the same
    TSC value as the host. With this update, the TSC offset
    has been updated to show the correct values. (BZ#656984)

  - Setting the boot settings of a virtual machine to,
    firstly, boot from PXE and, secondly, to boot from the
    hard drive would result in a PXE boot loop, that is, the
    virtual machine would not continue to boot from the hard
    drive if the PXE boot failed. This was caused by a flaw
    in the 'bochs-bios' (part of KVM) code. With this
    update, after a virtual machine tries to boot from PXE
    and fails, it continues to boot from a hard drive if
    there is one present. (BZ#659850)

  - If a 64-bit Scientific Linux 5.5 virtual machine was
    migrated to another host with a different CPU clock
    speed, the clock of that virtual machine would
    consistently lose or gain time (approximately half a
    second for every second the host is running). On
    machines that do not use the kvm clock, the network time
    protocol daemon (ntpd) could correct the time drifts
    caused by migration. However, using the pvclock caused
    the time to change consistently. This was due to flaws
    in the save/load functions of pvclock. With this update,
    the issue has been fixed and migrating a virtual machine
    no longer causes time drift. (BZ#660239)

The following procedure must be performed before this update will take
effect :

1) Stop all KVM guest virtual machines.

2) Either reboot the hypervisor machine or, as the root user, remove
(using 'modprobe -r [module]') and reload (using 'modprobe [module]')
all of the following modules which are currently running (determined
using 'lsmod'): kvm, ksm, kvm-intel or kvm-amd.

3) Restart the KVM guest virtual machines."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1012&L=scientific-linux-errata&T=0&P=1661
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e4d3584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=656984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=659850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660239"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-83-164.el5_5.30")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-83-164.el5_5.30")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-qemu-img-83-164.el5_5.30")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-tools-83-164.el5_5.30")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
