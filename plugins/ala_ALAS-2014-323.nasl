#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-323.
#

include("compat.inc");

if (description)
{
  script_id(73651);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2013-7345");
  script_xref(name:"ALAS", value:"2014-323");

  script_name(english:"Amazon Linux AMI : file (ALAS-2014-323)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The BEGIN regular expression in the awk script detector in
magic/Magdir/commands in file before 5.15 uses multiple wildcards with
unlimited repetitions, which allows context-dependent attackers to
cause a denial of service (CPU consumption) via a crafted ASCII file
that triggers a large amount of backtracking, as demonstrated via a
file with many newline characters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-323.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update file' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/23");
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
if (rpm_check(release:"ALA", reference:"file-5.11-13.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-debuginfo-5.11-13.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-devel-5.11-13.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-libs-5.11-13.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-static-5.11-13.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python-magic-5.11-13.16.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-devel / file-libs / file-static / etc");
}
