#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61195);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/28 11:42:29 $");

  script_cve_id("CVE-2011-4111");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL6.x x86_64");
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
"KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space
component for running virtual machines using KVM.

It was found that qemu-kvm did not properly drop supplemental group
privileges when the root user started guests from the command line
('/usr/libexec/qemu-kvm') with the '-runas' option. A qemu-kvm process
started this way could use this flaw to gain access to files on the
host that are accessible to the supplementary groups and not
accessible to the primary group. (CVE-2011-2527)

Note: This issue only affected qemu-kvm when it was started directly
from the command line. It did not affect applications that start
qemu-kvm via libvirt, such as the Virtual Machine Manager
(virt-manager).

A flaw was found in the way qemu-kvm handled VSC_ATR messages when a
guest was configured for a CCID (Chip/Smart Card Interface Devices)
USB smart card reader in passthrough mode. An attacker able to connect
to the port on the host being used for such a device could use this
flaw to crash the qemu-kvm process on the host or, possibly, escalate
their privileges on the host. (CVE-2011-4111)

All users of qemu-kvm should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, shut down all running virtual machines. Once all virtual
machines have shut down, start them again for this update to take
effect.

A number of additional packages were added to the security repository
so that this package could be installed on older SL systems."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1201&L=scientific-linux-errata&T=0&P=193
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36ed1087"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.209.el6_2.1")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.209.el6_2.1")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-debuginfo-0.12.1.2-2.209.el6_2.1")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.209.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
