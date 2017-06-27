#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0993 and 
# Oracle Linux Security Advisory ELSA-2007-0993 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67595);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-4571", "CVE-2007-4997", "CVE-2007-5494");
  script_bugtraq_id(25807, 26337);
  script_osvdb_id(39234, 39236, 44153);
  script_xref(name:"RHSA", value:"2007:0993");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2007-0993)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0993 :

Updated kernel packages that fix various security issues in the Red
Hat Enterprise Linux 5 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the following security
issues :

A memory leak was found in the Red Hat Content Accelerator kernel
patch. A local user could use this flaw to cause a denial of service
(memory exhaustion). (CVE-2007-5494, Important)

A flaw was found in the handling of IEEE 802.11 frames affecting
several wireless LAN modules. In certain circumstances, a remote
attacker could trigger this flaw by sending a malicious packet over a
wireless network and cause a denial of service (kernel crash).
(CVE-2007-4997, Important).

A flaw was found in the Advanced Linux Sound Architecture (ALSA). A
local user who had the ability to read the /proc/driver/snd-page-alloc
file could see portions of kernel memory. (CVE-2007-4571, Moderate).

In addition to the security issues described above, several bug fixes
preventing possible memory corruption, system crashes, SCSI I/O fails,
networking drivers performance regression and journaling block device
layer issue were also included.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
packages, which contain backported patches to resolve these issues.

Red Hat would like to credit Vasily Averin, Chris Evans, and Neil
Kettle for reporting the security issues corrected by this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000419.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-53.1.4.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-53.1.4.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
