#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-368.
#

include("compat.inc");

if (description)
{
  script_id(78311);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/25 14:45:27 $");

  script_cve_id("CVE-2014-0206", "CVE-2014-4014", "CVE-2014-4508", "CVE-2014-4608");
  script_xref(name:"ALAS", value:"2014-368");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2014-368)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"arch/x86/kernel/entry_32.S in the Linux kernel through 3.15.1 on
32-bit x86 platforms, when syscall auditing is enabled and the sep CPU
feature flag is set, allows local users to cause a denial of service
(OOPS and system crash) via an invalid syscall number, as demonstrated
by number 1000.

Array index error in the aio_read_events_ring function in fs/aio.c in
the Linux kernel through 3.15.1 allows local users to obtain sensitive
information from kernel memory via a large head value.

The capabilities implementation in the Linux kernel before 3.14.8 does
not properly consider that namespaces are inapplicable to inodes,
which allows local users to bypass intended chmod restrictions by
first creating a user namespace, as demonstrated by setting the setgid
bit on a file with group ownership of root.

** DISPUTED ** Multiple integer overflows in the lzo1x_decompress_safe
function in lib/lzo/lzo1x_decompress_safe.c in the LZO decompressor in
the Linux kernel before 3.15.2 allow context-dependent attackers to
cause a denial of service (memory corruption) via a crafted Literal
Run. NOTE: the author of the LZO algorithms says 'the Linux kernel is
*not* affected; media hype.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-368.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-3.10.48-55.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-3.10.48-55.140.amzn1")) flag++;

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
