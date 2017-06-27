#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0624. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81661);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/06 14:56:53 $");

  script_cve_id("CVE-2014-3640", "CVE-2014-7815", "CVE-2014-7840", "CVE-2014-8106");
  script_xref(name:"RHSA", value:"2015:0624");

  script_name(english:"RHEL 7 : qemu-kvm-rhev (RHSA-2015:0624)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm-rhev packages that fix multiple security issues,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Virtualization Hypervisor 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm-rhev package
provides the user-space component for running virtual machines using
KVM, in environments managed by Red Hat Enterprise Virtualization
Manager.

It was found that the Cirrus blit region checks were insufficient. A
privileged guest user could use this flaw to write outside of
VRAM-allocated buffer boundaries in the host's QEMU process address
space with attacker-provided data. (CVE-2014-8106)

An uninitialized data structure use flaw was found in the way the
set_pixel_format() function sanitized the value of bits_per_pixel. An
attacker able to access a guest's VNC console could use this flaw to
crash the guest. (CVE-2014-7815)

It was found that certain values that were read when loading RAM
during migration were not validated. A user able to alter the savevm
data (either on the disk or over the wire during migration) could use
either of these flaws to corrupt QEMU process memory on the
(destination) host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-7840)

A NULL pointer dereference flaw was found in the way QEMU handled UDP
packets with a source port and address of 0 when QEMU's user
networking was in use. A local guest user could use this flaw to crash
the guest. (CVE-2014-3640)

Red Hat would like to thank James Spadaro of Cisco for reporting
CVE-2014-7815, and Xavier Mehrenberger and Stephane Duverger of Airbus
for reporting CVE-2014-3640. The CVE-2014-8106 issue was found by
Paolo Bonzini of Red Hat, and the CVE-2014-7840 issue was discovered
by Michael S. Tsirkin of Red Hat.

This update provides the enhanced version of the qemu-kvm-rhev
packages for Red Hat Enterprise Virtualization (RHEV) Hypervisor,
which also fixes several bugs and adds various enhancements.

All Red Hat Enterprise Virtualization users with deployed
virtualization hosts are advised to install these updated packages,
which add this enhancement. After installing this update, shut down
all running virtual machines. Once all virtual machines have shut
down, start them again for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3640.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0624.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard-devel-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard-tools-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools-rhev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-devel-rhev-2.1.2-23.el7")) flag++;
if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-rhev-2.1.2-23.el7")) flag++;
if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-tools-rhev-2.1.2-23.el7")) flag++;
if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-img-rhev-2.1.2-23.el7")) flag++;
if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-common-rhev-2.1.2-23.el7")) flag++;
if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-rhev-2.1.2-23.el7")) flag++;
if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-tools-rhev-2.1.2-23.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard-devel-rhev / libcacard-rhev / libcacard-tools-rhev / etc");
}
