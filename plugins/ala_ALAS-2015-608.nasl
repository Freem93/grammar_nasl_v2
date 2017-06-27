#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-608.
#

include("compat.inc");

if (description)
{
  script_id(86770);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");
  script_xref(name:"ALAS", value:"2015-608");
  script_xref(name:"RHSA", value:"2015:1981");

  script_name(english:"Amazon Linux AMI : nspr / nss-util,nss,jss (ALAS-2015-608)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A use-after-poison flaw and a heap-based buffer overflow flaw were
found in the way NSS parsed certain ASN.1 structures. An attacker
could use these flaws to cause NSS to crash or execute arbitrary code
with the permissions of the user running an application compiled
against the NSS library. (CVE-2015-7181 , CVE-2015-7182)

A heap-based buffer overflow was found in NSPR. An attacker could use
this flaw to cause NSPR to crash or execute arbitrary code with the
permissions of the user running an application compiled against the
NSPR library. (CVE-2015-7183)

Note: Applications using NSPR's PL_ARENA_ALLOCATE, PR_ARENA_ALLOCATE,
PL_ARENA_GROW, or PR_ARENA_GROW macros need to be rebuild against the
fixed nspr packages to completely resolve the CVE-2015-7183 issue.
This erratum includes nss and nss-utils packages rebuilt against the
fixed nspr version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-608.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update nspr' to update your system.

Run 'yum update nss-util' to update your system.

Run 'yum update nss' to update your system.

Run 'yum update jss' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/06");
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
if (rpm_check(release:"ALA", reference:"jss-4.2.6-35.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jss-debuginfo-4.2.6-35.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jss-javadoc-4.2.6-35.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nspr-4.10.8-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nspr-debuginfo-4.10.8-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nspr-devel-4.10.8-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-3.19.1-7.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-debuginfo-3.19.1-7.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-devel-3.19.1-7.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-pkcs11-devel-3.19.1-7.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-sysinit-3.19.1-7.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-tools-3.19.1-7.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-3.19.1-4.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-debuginfo-3.19.1-4.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-devel-3.19.1-4.47.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jss / jss-debuginfo / jss-javadoc / nspr / nspr-debuginfo / etc");
}
