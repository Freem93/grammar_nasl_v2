#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-828.
#

include("compat.inc");

if (description)
{
  script_id(100106);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2017-2671", "CVE-2017-5967", "CVE-2017-7187", "CVE-2017-7308", "CVE-2017-7616", "CVE-2017-7618");
  script_xref(name:"ALAS", value:"2017-828");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-828)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Infinite recursion in ahash.c by triggering EBUSY on a full queue :

A vulnerability was found in crypto/ahash.c in the Linux kernel which
allows attackers to cause a denial of service (API operation calling
its own callback, and infinite recursion) by triggering EBUSY on a
full queue.(CVE-2017-7618)

Time subsystem allows local users to discover real PID values :

The time subsystem in the Linux kernel, when CONFIG_TIMER_STATS is
enabled, allows local users to discover real PID values (as
distinguished from PID values inside a PID namespace) by reading the
/proc/timer_list file, related to the print_timer function in
kernel/time/timer_list.c and the __timer_stats_timer_set_start_info
function in kernel/time/timer.c.(CVE-2017-5967)

Stack-based buffer overflow in sg_ioctl function :

The sg_ioctl function in drivers/scsi/sg.c in the Linux kernel allows
local users to cause a denial of service (stack-based buffer overflow)
or possibly have unspecified other impacts via a large command size in
an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds write access
in the sg_write function. (CVE-2017-7187)

Incorrect error handling in the set_mempolicy and mbind compat
syscalls in mm/mempolicy.c :

Incorrect error handling in the set_mempolicy() and mbind() compat
syscalls in mm/mempolicy.c; in the Linux kernel allows local users to
obtain sensitive information from uninitialized stack data by
triggering failure of a certain bitmap operation. (CVE-2017-7616)

Race condition in Link Layer Control :

A race condition leading to a NULL pointer dereference was found in
the Linux kernel's Link Layer Control implementation. A local attacker
with access to ping sockets could use this flaw to crash the system.
(CVE-2017-2671)

Overflow in check for priv area size :

It was found that the packet_set_ring() function of the Linux kernel's
networking implementation did not properly validate certain block-size
data. A local attacker with CAP_NET_RAW capability could use this flaw
to trigger a buffer overflow, resulting in the crash of the system.
Due to the nature of the flaw, privilege escalation cannot be fully
ruled out, although we believe it is unlikely. (CVE-2017-7308)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-828.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.27-14.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.27-14.31.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
