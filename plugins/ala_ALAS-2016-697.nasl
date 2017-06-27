#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-697.
#

include("compat.inc");

if (description)
{
  script_id(90866);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-3068", "CVE-2016-3069", "CVE-2016-3630");
  script_xref(name:"ALAS", value:"2016-697");

  script_name(english:"Amazon Linux AMI : mercurial (ALAS-2016-697)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Mercurial failed to properly check Git
sub-repository URLs. A Mercurial repository that includes a Git
sub-repository with a specially crafted URL could cause Mercurial to
execute arbitrary code. (CVE-2016-3068)

The binary delta decoder in Mercurial before 3.7.3 allows remote
attackers to execute arbitrary code via a (1) clone, (2) push, or (3)
pull command, related to (a) a list sizing rounding error and (b)
short records. (CVE-2016-3630)

It was discovered that the Mercurial convert extension failed to
sanitize special characters in Git repository names. A Git repository
with a specially crafted name could cause Mercurial to execute
arbitrary code when the Git repository was converted to a Mercurial
repository. (CVE-2016-3069)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-697.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mercurial' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-mercurial-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-python27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");
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
if (rpm_check(release:"ALA", reference:"emacs-mercurial-3.5.2-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-mercurial-el-3.5.2-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-common-3.5.2-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-debuginfo-3.5.2-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-python26-3.5.2-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-python27-3.5.2-1.26.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-mercurial / emacs-mercurial-el / mercurial-common / etc");
}
