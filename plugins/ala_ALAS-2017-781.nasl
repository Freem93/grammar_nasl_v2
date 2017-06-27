#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-781.
#

include("compat.inc");

if (description)
{
  script_id(96283);
  script_version("$Revision: 3.9 $");
  script_cvs_date("$Date: 2017/04/17 17:37:51 $");

  script_cve_id("CVE-2016-7426", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9310", "CVE-2016-9311");
  script_xref(name:"ALAS", value:"2017-781");

  script_name(english:"Amazon Linux AMI : ntp (ALAS-2017-781)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security-related issues were resolved :

CVE-2016-7426 : Client rate limiting and server responses

CVE-2016-7429 : Attack on interface selection

CVE-2016-7433 : Broken initial sync calculations regression

CVE-2016-9310 : Mode 6 unauthenticated trap information disclosure and
DDoS vector

CVE-2016-9311 : NULL pointer dereference when trap service is enabled"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-781.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ntp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ntp-4.2.6p5-43.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-debuginfo-4.2.6p5-43.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-doc-4.2.6p5-43.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-perl-4.2.6p5-43.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntpdate-4.2.6p5-43.33.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate");
}
