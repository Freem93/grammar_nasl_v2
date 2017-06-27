#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-726.
#

include("compat.inc");

if (description)
{
  script_id(92661);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-1237", "CVE-2016-4470", "CVE-2016-5243", "CVE-2016-5244", "CVE-2016-5696");
  script_xref(name:"ALAS", value:"2016-726");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2016-726)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that nfsd is missing permissions check when setting ACL
on files, this may allow a local users to gain access to any file by
setting a crafted ACL. (CVE-2016-1237)

A flaw was found in the Linux kernel's keyring handling code, where in
key_reject_and_link() an uninitialised variable would eventually lead
to arbitrary free address which could allow attacker to use a
use-after-free style attack. (CVE-2016-4470)

A leak of information was possible when issuing a netlink command of
the stack memory area leading up to this function call. An attacker
could use this to determine stack information for use in a later
exploit. (CVE-2016-5243)

A vulnerability was found in the Linux kernel in function
rds_inc_info_copy of file net/rds/recv.c. The last field 'flags' of
object 'minfo' is not initialized. This can leak data previously at
the flags location to userspace. (CVE-2016-5244)

A flaw was found in the implementation of the Linux kernel's handling
of networking challenge ack where an attacker is able to determine the
shared counter which could be used to determine sequence numbers for
TCP stream injection. (CVE-2016-5696)

(Updated on 2016-08-17: CVE-2016-5696 was fixed in this release but
was not previously part of this errata)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-726.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/02");
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
if (rpm_check(release:"ALA", reference:"kernel-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.4.15-25.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.4.15-25.57.amzn1")) flag++;

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
