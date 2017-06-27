#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-139.
#

include("compat.inc");

if (description)
{
  script_id(69629);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2012-4466");
  script_xref(name:"ALAS", value:"2012-139");

  script_name(english:"Amazon Linux AMI : ruby (ALAS-2012-139)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ruby 1.8.7 before patchlevel 371, 1.9.3 before patchlevel 286, and 2.0
before revision r37068 allows context-dependent attackers to bypass
safe-level restrictions and modify untainted strings via the
name_err_mesg_to_str API function, which marks the string as tainted,
a different vulnerability than CVE-2011-1005 ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-139.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/23");
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
if (rpm_check(release:"ALA", reference:"ruby-1.8.7.371-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-debuginfo-1.8.7.371-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-devel-1.8.7.371-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-irb-1.8.7.371-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-libs-1.8.7.371-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-rdoc-1.8.7.371-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-ri-1.8.7.371-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-static-1.8.7.371-1.20.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-irb / ruby-libs / etc");
}
