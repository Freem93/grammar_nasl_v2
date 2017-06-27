#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-790.
#

include("compat.inc");

if (description)
{
  script_id(96808);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/06 15:09:15 $");

  script_cve_id("CVE-2016-8318", "CVE-2016-8327", "CVE-2017-3238", "CVE-2017-3244", "CVE-2017-3257", "CVE-2017-3258", "CVE-2017-3273", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318");
  script_xref(name:"ALAS", value:"2017-790");

  script_name(english:"Amazon Linux AMI : mysql56 (ALAS-2017-790)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security-related issues were fixed :

CVE-2016-8318 Server: Security: Encryption unspecified vulnerability

CVE-2016-8327 Server: Replication unspecified vulnerability

CVE-2017-3238 Server: Optimizer unspecified vulnerability

CVE-2017-3244 Server: DML unspecified vulnerability

CVE-2017-3257 Server: InnoDB unspecified vulnerability

CVE-2017-3258 Server: DDL unspecified vulnerability

CVE-2017-3273 Server: DDL unspecified vulnerability

CVE-2017-3313 Server: MyISAM unspecified vulnerability

CVE-2017-3317 Logging unspecified vulnerability

CVE-2017-3318 Server: Error Handling unspecified vulnerability"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-790.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");
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
if (rpm_check(release:"ALA", reference:"mysql56-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-bench-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-common-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-debuginfo-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-devel-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-devel-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-errmsg-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-libs-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-server-5.6.35-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-test-5.6.35-1.23.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql56 / mysql56-bench / mysql56-common / mysql56-debuginfo / etc");
}
