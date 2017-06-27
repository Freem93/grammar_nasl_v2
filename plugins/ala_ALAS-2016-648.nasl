#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-648.
#

include("compat.inc");

if (description)
{
  script_id(88660);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2013-4312", "CVE-2015-8709", "CVE-2015-8767", "CVE-2016-0723");
  script_xref(name:"ALAS", value:"2016-648");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2016-648)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux kernel before 4.4.1 allows local users to bypass
file-descriptor limits and cause a denial of service (memory
consumption) by sending each descriptor over a UNIX socket before
closing it, related to net/unix/af_unix.c and net/unix/garbage.c.
(CVE-2013-4312)

A race condition in the tty_ioctl function in drivers/tty/tty_io.c in
the Linux kernel through 4.4.1 was found that allows local users to
obtain sensitive information from kernel memory or cause a denial of
service (use-after-free and system crash) by making a TIOCGETD ioctl
call during processing of a TIOCSETD ioctl call. (CVE-2016-0723)

A privilege-escalation vulnerability was discovered in the Linux
kernel built with User Namespace (CONFIG_USER_NS) support. The flaw
occurred when the ptrace() system call was used on a root-owned
process to enter a user namespace. A privileged namespace user could
exploit this flaw to potentially escalate their privileges on the
system, outside the original namespace. (CVE-2015-8709)

net/sctp/sm_sideeffect.c in the Linux kernel before 4.3 does not
properly manage the relationship between a lock and a socket, which
allows local users to cause a denial of service (deadlock) via a
crafted sctp_accept call. (CVE-2015-8767)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-648.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum clean all' followed by 'yum update kernel' to update your
system. You will need to reboot your system in order for the new
kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.1.17-22.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.1.17-22.30.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
