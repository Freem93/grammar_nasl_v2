#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60837);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/06 11:47:00 $");

  script_cve_id("CVE-2010-0431", "CVE-2010-0435", "CVE-2010-2784");

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
"It was found that QEMU-KVM on the host did not validate all pointers
provided from a guest system's QXL graphics card driver. A privileged
guest user could use this flaw to cause the host to dereference an
invalid pointer, causing the guest to crash (denial of service) or,
possibly, resulting in the privileged guest user escalating their
privileges on the host. (CVE-2010-0431)

A flaw was found in QEMU-KVM, allowing the guest some control over the
index used to access the callback array during sub-page MMIO
initialization. A privileged guest user could use this flaw to crash
the guest (denial of service) or, possibly, escalate their privileges
on the host. (CVE-2010-2784)

A NULL pointer dereference flaw was found when the host system had a
processor with the Intel VT-x extension enabled. A privileged guest
user could use this flaw to trick the host into emulating a certain
instruction, which could crash the host (denial of service).
(CVE-2010-0435)

This update also fixes the following bugs :

  - running a 'qemu-img' check on a faulty virtual machine
    image ended with a segmentation fault. With this update,
    the segmentation fault no longer occurs when running the
    'qemu-img' check. (BZ#610342)

  - when attempting to transfer a file between two guests
    that were joined in the same virtual LAN (VLAN), the
    receiving guest unexpectedly quit. With this update, the
    transfer completes successfully. (BZ#610343)

  - installation of a system was occasionally failing in
    KVM. This was caused by KVM using wrong permissions for
    large guest pages. With this update, the installation
    completes successfully. (BZ#616796)

  - previously, the migration process would fail for a
    virtual machine because the virtual machine could not
    map all the memory. This was caused by a conflict that
    was initiated when a virtual machine was initially run
    and then migrated right away. With this update, the
    conflict no longer occurs and the migration process no
    longer fails. (BZ#618205)

  - using a thinly provisioned VirtIO disk on iSCSI storage
    and performing a 'qemu-img' check during an 'e_no_space'
    event returned cluster errors. With this update, the
    errors no longer appear. (BZ#618206)

NOTE: The following procedure must be performed before this update
will take effect :

1) Stop all KVM guest virtual machines.

2) Either reboot the hypervisor machine or, as the root user, remove
(using 'modprobe -r [module]') and reload (using 'modprobe [module]')
all of the following modules which are currently running (determined
using 'lsmod'): kvm, ksm, kvm-intel or kvm-amd.

3) Restart the KVM guest virtual machines."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=1755
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd19f1a8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=610342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=610343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=616796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=618205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=618206"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-83-164.el5_5.21")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-83-164.el5_5.21")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-qemu-img-83-164.el5_5.21")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-tools-83-164.el5_5.21")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
