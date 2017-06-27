#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-142.
#

include("compat.inc");

if (description)
{
  script_id(69632);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2012-0957", "CVE-2012-1568", "CVE-2012-2133", "CVE-2012-3400", "CVE-2012-3511", "CVE-2012-4508", "CVE-2012-4565");
  script_xref(name:"ALAS", value:"2012-142");
  script_xref(name:"RHSA", value:"2012:1426");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2012-142)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-free flaw was found in the Linux kernel's memory
management subsystem in the way quota handling for huge pages was
performed. A local, unprivileged user could use this flaw to cause a
denial of service or, potentially, escalate their privileges.
(CVE-2012-2133 , Moderate)

A use-after-free flaw was found in the madvise() system call
implementation in the Linux kernel. A local, unprivileged user could
use this flaw to cause a denial of service or, potentially, escalate
their privileges. (CVE-2012-3511 , Moderate)

It was found that when running a 32-bit binary that uses a large
number of shared libraries, one of the libraries would always be
loaded at a predictable address in memory. An attacker could use this
flaw to bypass the Address Space Layout Randomization (ASLR) security
feature. (CVE-2012-1568 , Low)

Buffer overflow flaws were found in the udf_load_logicalvol() function
in the Universal Disk Format (UDF) file system implementation in the
Linux kernel. An attacker with physical access to a system could use
these flaws to cause a denial of service or escalate their privileges.
(CVE-2012-3400 , Low)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-142.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.2.34-55.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.2.34-55.46.amzn1")) flag++;

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
