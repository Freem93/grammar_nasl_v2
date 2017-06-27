#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-292.
#

include("compat.inc");

if (description)
{
  script_id(72748);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-1912");
  script_xref(name:"ALAS", value:"2014-292");

  script_name(english:"Amazon Linux AMI : python26 (ALAS-2014-292)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in the socket.recvfrom_into function in
Modules/socketmodule.c in Python 2.5 before 2.7.7, 3.x before 3.3.4,
and 3.4.x before 3.4rc1 allows remote attackers to execute arbitrary
code via a crafted string."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-292.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python26' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/02");
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
if (rpm_check(release:"ALA", reference:"python26-2.6.9-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-debuginfo-2.6.9-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-devel-2.6.9-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-libs-2.6.9-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-test-2.6.9-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-tools-2.6.9-1.43.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python26 / python26-debuginfo / python26-devel / python26-libs / etc");
}
