#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-458.
#

include("compat.inc");

if (description)
{
  script_id(79842);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2013-6435", "CVE-2014-8118");
  script_xref(name:"ALAS", value:"2014-458");

  script_name(english:"Amazon Linux AMI : rpm (ALAS-2014-458)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that RPM could encounter an integer overflow, leading to
a stack-based overflow, while parsing a crafted CPIO header in the
payload section of an RPM file. This could allow an attacker to modify
signed RPM files in such a way that they would execute code chosen by
the attacker during package installation. (CVE-2014-8118)

It was found that RPM wrote file contents to the target installation
directory under a temporary name, and verified its cryptographic
signature only after the temporary file has been written completely.
Under certain conditions, the system interprets the unverified
temporary file contents and extracts commands from it. This could
allow an attacker to modify signed RPM files in such a way that they
would execute code chosen by the attacker during package installation.
Red Hat has published an excellent analysis of this issue.
(CVE-2013-6435)"
  );
  # https://securityblog.redhat.com/2014/12/10/analysis-of-the-cve-2013-6435-flaw-in-rpm/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed8ff264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-458.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update rpm' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-build-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/10");
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
if (rpm_check(release:"ALA", reference:"rpm-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-apidocs-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-build-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-build-libs-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-cron-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-debuginfo-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-devel-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-libs-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-python-4.11.2-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-sign-4.11.2-2.58.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rpm / rpm-apidocs / rpm-build / rpm-build-libs / rpm-cron / etc");
}
