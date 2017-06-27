#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-672.
#

include("compat.inc");

if (description)
{
  script_id(90154);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_xref(name:"ALAS", value:"2016-672");

  script_name(english:"Amazon Linux AMI : git (ALAS-2016-672)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer truncation flaw (CVE-2016-2315) and an integer overflow
flaw (CVE-2016-2324), both leading to a heap-based buffer overflow,
were found in the way Git processed certain path information. A remote
attacker could create a specially crafted Git repository that would
cause a Git client or server to crash or, possibly, execute arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-672.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update git' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");
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
if (rpm_check(release:"ALA", reference:"emacs-git-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-git-el-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-all-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-bzr-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-cvs-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-daemon-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-debuginfo-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-email-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-hg-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-p4-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-svn-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gitweb-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-2.7.4-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-SVN-2.7.4-1.47.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}