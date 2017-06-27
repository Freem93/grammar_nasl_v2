#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0627 and 
# CentOS Errata and Security Advisory 2010:0627 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48910);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/28 23:54:23 $");

  script_cve_id("CVE-2010-0431", "CVE-2010-0435", "CVE-2010-2784");
  script_osvdb_id(67473, 67474, 67475);
  script_xref(name:"RHSA", value:"2010:0627");

  script_name(english:"CentOS 5 : kvm (CESA-2010:0627)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix three security issues and multiple bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

It was found that QEMU-KVM on the host did not validate all pointers
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

* running a 'qemu-img' check on a faulty virtual machine image ended
with a segmentation fault. With this update, the segmentation fault no
longer occurs when running the 'qemu-img' check. (BZ#610342)

* when attempting to transfer a file between two guests that were
joined in the same virtual LAN (VLAN), the receiving guest
unexpectedly quit. With this update, the transfer completes
successfully. (BZ#610343)

* installation of a system was occasionally failing in KVM. This was
caused by KVM using wrong permissions for large guest pages. With this
update, the installation completes successfully. (BZ#616796)

* previously, the migration process would fail for a virtual machine
because the virtual machine could not map all the memory. This was
caused by a conflict that was initiated when a virtual machine was
initially run and then migrated right away. With this update, the
conflict no longer occurs and the migration process no longer fails.
(BZ#618205)

* using a thinly provisioned VirtIO disk on iSCSI storage and
performing a 'qemu-img' check during an 'e_no_space' event returned
cluster errors. With this update, the errors no longer appear.
(BZ#618206)

All KVM users should upgrade to these updated packages, which contain
backported patches to resolve these issues. Note: The procedure in the
Solution section must be performed before this update will take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7d5bb81"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-164.el5_5.21")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-164.el5_5.21")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-164.el5_5.21")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-164.el5_5.21")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
