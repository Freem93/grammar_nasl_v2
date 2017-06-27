#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1971 and 
# CentOS Errata and Security Advisory 2014:1971 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79876);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2013-2929", "CVE-2014-1739", "CVE-2014-3181", "CVE-2014-3182", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3631", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-4027", "CVE-2014-4652", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-5045", "CVE-2014-6410");
  script_bugtraq_id(64111, 68048, 68159, 68162, 68163, 68170, 68862, 69763, 69768, 69770, 69779, 69781, 69799, 70095, 70766, 70768, 70883);
  script_osvdb_id(107819, 108001, 108386, 108389, 108390, 108451, 110565, 110567, 110568, 110569, 110570, 110571, 110572, 110732, 111406, 111409, 111430, 113724, 113726, 113727);
  script_xref(name:"RHSA", value:"2014:1971");

  script_name(english:"CentOS 7 : kernel (CESA-2014:1971)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's SCTP implementation
handled malformed or duplicate Address Configuration Change Chunks
(ASCONF). A remote attacker could use either of these flaws to crash
the system. (CVE-2014-3673, CVE-2014-3687, Important)

* A flaw was found in the way the Linux kernel's SCTP implementation
handled the association's output queue. A remote attacker could send
specially crafted packets that would cause the system to use an
excessive amount of memory, leading to a denial of service.
(CVE-2014-3688, Important)

* Two flaws were found in the way the Apple Magic Mouse/Trackpad
multi-touch driver and the Minibox PicoLCD driver handled invalid HID
reports. An attacker with physical access to the system could use
these flaws to crash the system or, potentially, escalate their
privileges on the system. (CVE-2014-3181, CVE-2014-3186, Moderate)

* A memory corruption flaw was found in the way the USB ConnectTech
WhiteHEAT serial driver processed completion commands sent via USB
Request Blocks buffers. An attacker with physical access to the system
could use this flaw to crash the system or, potentially, escalate
their privileges on the system. (CVE-2014-3185, Moderate)

* A flaw was found in the way the Linux kernel's keys subsystem
handled the termination condition in the associative array garbage
collection functionality. A local, unprivileged user could use this
flaw to crash the system. (CVE-2014-3631, Moderate)

* Multiple flaws were found in the way the Linux kernel's ALSA
implementation handled user controls. A local, privileged user could
use either of these flaws to crash the system. (CVE-2014-4654,
CVE-2014-4655, CVE-2014-4656, Moderate)

* A flaw was found in the way the Linux kernel's VFS subsystem handled
reference counting when performing unmount operations on symbolic
links. A local, unprivileged user could use this flaw to exhaust all
available memory on the system or, potentially, trigger a
use-after-free error, resulting in a system crash or privilege
escalation. (CVE-2014-5045, Moderate)

* A flaw was found in the way the get_dumpable() function return value
was interpreted in the ptrace subsystem of the Linux kernel. When
'fs.suid_dumpable' was set to 2, a local, unprivileged local user
could use this flaw to bypass intended ptrace restrictions and obtain
potentially sensitive information. (CVE-2013-2929, Low)

* A stack overflow flaw caused by infinite recursion was found in the
way the Linux kernel's UDF file system implementation processed
indirect ICBs. An attacker with physical access to the system could
use a specially crafted UDF image to crash the system. (CVE-2014-6410,
Low)

* An information leak flaw in the way the Linux kernel handled media
device enumerate entities IOCTL requests could allow a local user able
to access the /dev/media0 device file to leak kernel memory bytes.
(CVE-2014-1739, Low)

* An out-of-bounds read flaw in the Logitech Unifying receiver driver
could allow an attacker with physical access to the system to crash
the system or, potentially, escalate their privileges on the system.
(CVE-2014-3182, Low)

* Multiple out-of-bounds write flaws were found in the way the Cherry
Cymotion keyboard driver, KYE/Genius device drivers, Logitech device
drivers, Monterey Genius KB29E keyboard driver, Petalynx Maxter remote
control driver, and Sunplus wireless desktop driver handled invalid
HID reports. An attacker with physical access to the system could use
either of these flaws to write data past an allocated memory buffer.
(CVE-2014-3184, Low)

* An information leak flaw was found in the RAM Disks Memory Copy
(rd_mcp) back end driver of the iSCSI Target subsystem could allow a
privileged user to leak the contents of kernel memory to an iSCSI
initiator remote client. (CVE-2014-4027, Low)

* An information leak flaw in the Linux kernel's ALSA implementation
could allow a local, privileged user to leak kernel memory to user
space. (CVE-2014-4652, Low)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020820.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?440efca7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-123.13.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-123.13.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
