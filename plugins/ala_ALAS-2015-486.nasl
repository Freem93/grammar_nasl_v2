#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-486.
#

include("compat.inc");

if (description)
{
  script_id(81674);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/09 13:33:13 $");

  script_cve_id("CVE-2014-9328");
  script_xref(name:"ALAS", value:"2015-486");

  script_name(english:"Amazon Linux AMI : clamav (ALAS-2015-486)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ClamAV before 0.98.6 allows remote attackers to have unspecified
impact via a crafted upack packer file, related to a 'heap out of
bounds condition.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-486.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update clamav' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-data-empty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-milter-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-scanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-scanner-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-server-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-update");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"clamav-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-empty-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-db-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-debuginfo-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-devel-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-filesystem-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-lib-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-sysvinit-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-scanner-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-scanner-sysvinit-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-server-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-server-sysvinit-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-update-0.98.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamd-0.98.6-1.11.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-data / clamav-data-empty / clamav-db / etc");
}
