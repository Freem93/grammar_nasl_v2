#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1507 and 
# Oracle Linux Security Advisory ELSA-2015-1507 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85035);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/12/04 14:38:00 $");

  script_cve_id("CVE-2015-3214", "CVE-2015-5154");
  script_osvdb_id(123468, 125389);
  script_xref(name:"RHSA", value:"2015:1507");

  script_name(english:"Oracle Linux 7 : qemu-kvm (ELSA-2015-1507)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1507 :

Updated qemu-kvm packages that fix two security issues and one bug are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

A heap buffer overflow flaw was found in the way QEMU's IDE subsystem
handled I/O buffer access while processing certain ATAPI commands. A
privileged guest user in a guest with the CDROM drive enabled could
potentially use this flaw to execute arbitrary code on the host with
the privileges of the host's QEMU process corresponding to the guest.
(CVE-2015-5154)

An out-of-bounds memory access flaw, leading to memory corruption or
possibly an information leak, was found in QEMU's pit_ioport_read()
function. A privileged guest user in a QEMU guest, which had QEMU PIT
emulation enabled, could potentially, in rare cases, use this flaw to
execute arbitrary code on the host with the privileges of the hosting
QEMU process. (CVE-2015-3214)

Red Hat would like to thank Matt Tait of Google's Project Zero
security team for reporting the CVE-2015-3214 issue. The CVE-2015-5154
issue was discovered by Kevin Wolf of Red Hat.

This update also fixes the following bug :

* Due to an incorrect implementation of portable memory barriers, the
QEMU emulator in some cases terminated unexpectedly when a virtual
disk was under heavy I/O load. This update fixes the implementation in
order to achieve correct synchronization between QEMU's threads. As a
result, the described crash no longer occurs. (BZ#1233643)

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005221.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcacard-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-img-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-86.el7_1.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard / libcacard-devel / libcacard-tools / qemu-img / qemu-kvm / etc");
}
