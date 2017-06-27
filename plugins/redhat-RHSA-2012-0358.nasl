#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0358. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64030);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/18 18:39:01 $");

  script_cve_id("CVE-2011-1898", "CVE-2011-2699", "CVE-2011-4127", "CVE-2011-4330", "CVE-2012-0028");
  script_bugtraq_id(48515, 48802, 50750, 51176, 51947);
  script_xref(name:"RHSA", value:"2012:0358");

  script_name(english:"RHEL 5 : kernel (RHSA-2012:0358)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and various
bugs are now available for Red Hat Enterprise Linux 5.6 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* Using PCI passthrough without interrupt remapping support allowed
Xen hypervisor guests to generate MSI interrupts and thus potentially
inject traps. A privileged guest user could use this flaw to crash the
host or possibly escalate their privileges on the host. The fix for
this issue can prevent PCI passthrough working and guests starting.
Refer to Red Hat Bugzilla bug 715555 for details. (CVE-2011-1898,
Important)

* IPv6 fragment identification value generation could allow a remote
attacker to disrupt a target system's networking, preventing
legitimate users from accessing its services. (CVE-2011-2699,
Important)

* Using the SG_IO ioctl to issue SCSI requests to partitions or LVM
volumes resulted in the requests being passed to the underlying block
device. If a privileged user only had access to a single partition or
LVM volume, they could use this flaw to bypass those restrictions and
gain read and write access (and be able to issue other SCSI commands)
to the entire block device. Refer to Red Hat Knowledgebase article
67869, linked to in the References, for further details about this
issue. (CVE-2011-4127, Important)

* A flaw was found in the way the Linux kernel handled robust list
pointers of user-space held futexes across exec() calls. A local,
unprivileged user could use this flaw to cause a denial of service or,
eventually, escalate their privileges. (CVE-2012-0028, Important)

* A missing boundary check was found in the Linux kernel's HFS file
system implementation. A local attacker could use this flaw to cause a
denial of service or escalate their privileges by mounting a
specially crafted disk. (CVE-2011-4330, Moderate)

Red Hat would like to thank Fernando Gont for reporting CVE-2011-2699,
and Clement Lecigne for reporting CVE-2011-4330.

This update also fixes the following bugs :

* Previously, all timers for a Xen fully-virtualized domain were based
on the time stamp counter (TSC) of the underlying physical CPU. This
could cause observed time to go backwards on some hosts. This update
moves all timers except HPET to the Xen monotonic system time, which
fixes the bug as long as the HPET is removed from the configuration of
the domain. (BZ#773359)

* Previously, tests of the Microsoft Server Virtualization Validation
Program (SVVP) detected unreliability of the emulated HPET (High
Performance Event Timer) on some hosts. Now, HPET can be configured as
a per-domain configuration option; if it is disabled, the guest
chooses a more reliable timer source. Disabling HPET is suggested for
Windows guests, as well as fully-virtualized Linux guests that show
occasional 'time went backwards' errors in the console. (BZ#773360)

* SG_IO ioctls were not implemented correctly in the Red Hat
Enterprise Linux 5 virtio-blk driver. Sending an SG_IO ioctl request
to a virtio-blk disk caused the sending thread to enter an
uninterruptible sleep state ('D' state). With this update, SG_IO
ioctls are rejected by the virtio-blk driver; the ioctl system call
simply returns an ENOTTY ('Inappropriate ioctl for device') error and
the thread continues normally. (BZ#784658)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1898.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4127.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4330.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/articles/66747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=715555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/articles/67869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0358.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", reference:"kernel-doc-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"kernel-headers-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-headers-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-headers-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-devel-2.6.18-238.35.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-238.35.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
