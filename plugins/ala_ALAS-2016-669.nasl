#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-669.
#

include("compat.inc");

if (description)
{
  script_id(89966);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 14:29:49 $");

  script_cve_id("CVE-2016-2383", "CVE-2016-2550", "CVE-2016-2847", "CVE-2016-3157");
  script_xref(name:"ALAS", value:"2016-669");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2016-669)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When running as a Xen 64-bit PV guest, user mode processes not
supposed to be able to access I/O ports may be granted such
permission, potentially resulting in one or more of in-guest privilege
escalation, guest crashes (Denial of Service), or in-guest information
leaks. (CVE-2016-3157)

In some cases, the kernel did not correctly fix backward jumps in a
new eBPF program, which could allow arbitrary reads. (CVE-2016-2383)

The kernel incorrectly accounted for the number of in-flight fds over
a unix domain socket to the original opener of the file descriptor.
Another process could arbitrarily deplete the original file opener's
maximum open files resource limit. (CVE-2016-2550)

A resource-exhaustion vulnerability was found in the kernel, where an
unprivileged process could allocate and accumulate far more file
descriptors than the process' limit. A local, unauthenticated user
could exploit this flaw by sending file descriptors over a Unix socket
and then closing them to keep the process' fd count low, thereby
creating kernel-memory or file-descriptors exhaustion (denial of
service). (CVE-2016-2847)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-669.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");
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
if (rpm_check(release:"ALA", reference:"kernel-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.1.19-24.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.1.19-24.31.amzn1")) flag++;

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
