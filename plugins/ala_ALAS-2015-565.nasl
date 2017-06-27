#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-565.
#

include("compat.inc");

if (description)
{
  script_id(84925);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/14 14:25:18 $");

  script_cve_id("CVE-2015-1805", "CVE-2015-3212", "CVE-2015-5364", "CVE-2015-5366");
  script_xref(name:"ALAS", value:"2015-565");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2015-565)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the Linux kernel's implementation of vectored pipe
read and write functionality did not take into account the I/O vectors
that were already processed when retrying after a failed atomic access
operation, potentially resulting in memory corruption due to an I/O
vector array overrun. A local, unprivileged user could use this flaw
to crash the system or, potentially, escalate their privileges on the
system. (CVE-2015-1805)

A flaw was found in the Linux kernels handling of the SCTPs automatic
handling of dynamic multi-homed connections. A race condition in the
way the Linux kernel handles lists of associations in SCTP sockets
using Address Configuration Change messages, leading to list
corruption and panics. (CVE-2015-3212)

A flaw was found in the way the Linux kernel's networking
implementation handled UDP packets with incorrect checksum values. A
remote attacker could potentially use this flaw to trigger an infinite
loop in the kernel, resulting in a denial of service on the system, or
cause a denial of service in applications using the edge triggered
epoll functionality. (CVE-2015-5364)

A flaw was found in the way the Linux kernel's networking
implementation handled UDP packets with incorrect checksum values. A
remote attacker could potentially use this flaw to trigger an infinite
loop in the kernel, resulting in a denial of service on the system, or
cause a denial of service in applications using the edge triggered
epoll functionality. (CVE-2015-5366)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-565.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum clean all' followed by 'yum update kernel' to update your
system. You will need to reboot your system in order for the new
kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-3.14.48-33.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-3.14.48-33.39.amzn1")) flag++;

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
