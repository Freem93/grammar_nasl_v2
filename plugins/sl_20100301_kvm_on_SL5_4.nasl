#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60740);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id("CVE-2009-3722", "CVE-2010-0419");

  script_name(english:"Scientific Linux Security Update : kvm on SL5.4 x86_64");
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
"CVE-2009-3722 KVM: Check cpl before emulating debug register access

CVE-2010-0419 kvm: emulator privilege escalation segment selector
check

A flaw was found in the way the x86 emulator loaded segment selectors
(used for memory segmentation and protection) into segment registers.
In some guest system configurations, an unprivileged guest user could
leverage this flaw to crash the guest or possibly escalate their
privileges within the guest. (CVE-2010-0419)

The x86 emulator implementation was missing a check for the Current
Privilege Level (CPL) while accessing debug registers. An unprivileged
user in a guest could leverage this flaw to crash the guest.
(CVE-2009-3722)

This update also fixes the following bugs :

The return values of the bdrv_aio_write() and bdrv_aio_read()
functions were ignored. If an immediate failure occurred in one of
these functions, errors would be missed and the guest could hang or
read corrupted data. (BZ#562776)

The following procedure must be performed before this update will take
effect :

1) Stop all KVM guest virtual machines.

2) Either reboot the hypervisor machine or, as the root user, remove
(using 'modprobe -r [module]') and reload (using 'modprobe [module]')
all of the following modules which are currently running (determined
using 'lsmod'): kvm, ksm, kvm-intel or kvm-amd.

3) Restart the KVM guest virtual machines."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=199
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97ad82cc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=562776"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-83-105.el5_4.27")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-83-105.el5_4.27")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-qemu-img-83-105.el5_4.27")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-tools-83-105.el5_4.27")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
