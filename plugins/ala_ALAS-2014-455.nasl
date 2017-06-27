#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-455.
#

include("compat.inc");

if (description)
{
  script_id(79725);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-7841", "CVE-2014-7970", "CVE-2014-9090", "CVE-2014-9322");
  script_xref(name:"ALAS", value:"2014-455");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2014-455)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The sctp_process_param function in net/sctp/sm_make_chunk.c in the
SCTP implementation in the Linux kernel before 3.17.4, when ASCONF is
used, allows remote attackers to cause a denial of service (NULL
pointer dereference and system crash) via a malformed INIT chunk.
(CVE-2014-7841)

The pivot_root implementation in fs/namespace.c in the Linux kernel
through 3.17 does not properly interact with certain locations of a
chroot directory, which allows local users to cause a denial of
service (mount-tree loop) via . (dot) values in both arguments to the
pivot_root system call. (CVE-2014-7970)

The do_double_fault function in arch/x86/kernel/traps.c in the Linux
kernel through 3.17.4 does not properly handle faults associated with
the Stack Segment (SS) segment register, which allows local users to
cause a denial of service (panic) via a modify_ldt system call, as
demonstrated by sigreturn_32 in the linux-clock-tests test suite.
(CVE-2014-9090)

A flaw was found in the way the Linux kernel handled GS segment
register base switching when recovering from a #SS (stack segment)
fault on an erroneous return to user space. A local, unprivileged user
could use this flaw to escalate their privileges on the system.
(CVE-2014-9322)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-455.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum clean all' followed by 'yum update kernel' to update your
system. You will need to reboot your system in order for the new
kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-3.14.26-24.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-3.14.26-24.46.amzn1")) flag++;

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
