#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1272 and 
# CentOS Errata and Security Advisory 2015:1272 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85010);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/28 16:58:13 $");

  script_cve_id("CVE-2014-3184", "CVE-2014-3940", "CVE-2014-4652", "CVE-2014-8133", "CVE-2014-8709", "CVE-2014-9683", "CVE-2015-0239", "CVE-2015-3339");
  script_bugtraq_id(67786, 68170, 69768, 70965, 71684, 72643, 72842, 74243);
  script_osvdb_id(107650, 108386, 110567, 110568, 110569, 110570, 110571, 110572, 114393, 115920, 117762, 118625, 121170);
  script_xref(name:"RHSA", value:"2015:1272");

  script_name(english:"CentOS 6 : kernel (CESA-2015:1272)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, address
several hundred bugs, and add numerous enhancements are now available
as part of the ongoing support and maintenance of Red Hat Enterprise
Linux version 6. This is the seventh regular update.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way Linux kernel's Transparent Huge Pages
(THP) implementation handled non-huge page migration. A local,
unprivileged user could use this flaw to crash the kernel by migrating
transparent hugepages. (CVE-2014-3940, Moderate)

* A buffer overflow flaw was found in the way the Linux kernel's
eCryptfs implementation decoded encrypted file names. A local,
unprivileged user could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-9683,
Moderate)

* A race condition flaw was found between the chown and execve system
calls. When changing the owner of a setuid user binary to root, the
race condition could momentarily make the binary setuid root. A local,
unprivileged user could potentially use this flaw to escalate their
privileges on the system. (CVE-2015-3339, Moderate)

* Multiple out-of-bounds write flaws were found in the way the Cherry
Cymotion keyboard driver, KYE/Genius device drivers, Logitech device
drivers, Monterey Genius KB29E keyboard driver, Petalynx Maxter remote
control driver, and Sunplus wireless desktop driver handled HID
reports with an invalid report descriptor size. An attacker with
physical access to the system could use either of these flaws to write
data past an allocated memory buffer. (CVE-2014-3184, Low)

* An information leak flaw was found in the way the Linux kernel's
Advanced Linux Sound Architecture (ALSA) implementation handled access
of the user control's state. A local, privileged user could use this
flaw to leak kernel memory to user space. (CVE-2014-4652, Low)

* It was found that the espfix functionality could be bypassed by
installing a 16-bit RW data segment into GDT instead of LDT (which
espfix checks), and using that segment on the stack. A local,
unprivileged user could potentially use this flaw to leak kernel stack
addresses. (CVE-2014-8133, Low)

* An information leak flaw was found in the Linux kernel's IEEE 802.11
wireless networking implementation. When software encryption was used,
a remote attacker could use this flaw to leak up to 8 bytes of
plaintext. (CVE-2014-8709, Low)

* It was found that the Linux kernel KVM subsystem's sysenter
instruction emulation was not sufficient. An unprivileged guest user
could use this flaw to escalate their privileges by tricking the
hypervisor to emulate a SYSENTER instruction in 16-bit mode, if the
guest OS did not initialize the SYSENTER model-specific registers
(MSRs). Note: Certified guest operating systems for Red Hat Enterprise
Linux with KVM do initialize the SYSENTER MSRs and are thus not
vulnerable to this issue when running on a KVM hypervisor.
(CVE-2015-0239, Low)

Red Hat would like to thank Andy Lutomirski for reporting the
CVE-2014-8133 issue, and Nadav Amit for reporting the CVE-2015-0239
issue.

This update fixes several hundred bugs and adds numerous enhancements.
Refer to the Red Hat Enterprise Linux 6.7 Release Notes for
information on the most significant of these changes, and the
following Knowledgebase article for further information :

https://access.redhat.com/articles/1466073

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements. The system must be rebooted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/001863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f50d5a16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-573.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-573.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
