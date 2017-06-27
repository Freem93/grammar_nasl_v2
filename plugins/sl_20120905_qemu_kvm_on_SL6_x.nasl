#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61795);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/11/27 11:48:16 $");

  script_cve_id("CVE-2012-3515");

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

A flaw was found in the way QEMU handled VT100 terminal escape
sequences when emulating certain character devices. A guest user with
privileges to write to a character device that is emulated on the host
using a virtual console back-end could use this flaw to crash the
qemu-kvm process on the host or, possibly, escalate their privileges
on the host. (CVE-2012-3515)

This flaw did not affect the default use of KVM. Affected
configurations were :

  - When guests were started from the command line
    ('/usr/libexec/qemu-kvm') without the '-nodefaults'
    option, and also without specifying a serial or parallel
    device, or a virtio-console device, that specifically
    does not use a virtual console (vc) back-end. (Note that
    Red Hat does not support invoking 'qemu-kvm' from the
    command line without '-nodefaults' on Red Hat Enterprise
    Linux 6.)

  - Guests that were managed via libvirt, such as when using
    Virtual Machine Manager (virt-manager), but that have a
    serial or parallel device, or a virtio-console device,
    that uses a virtual console back-end. By default, guests
    managed via libvirt will not use a virtual console
    back-end for such devices.

All users of qemu-kvm should upgrade to these updated packages, which
resolve this issue. After installing this update, shut down all
running virtual machines. Once all virtual machines have shut down,
start them again for this update to take effect.

To resolve dependency issues, the usbredir packages have been added to
the repos."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=487
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0044811e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
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
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-guest-agent-0.12.1.2-2.295.el6_3.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.295.el6_3.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.295.el6_3.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.295.el6_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
