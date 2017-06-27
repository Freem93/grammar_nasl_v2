#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-701.
#

include("compat.inc");

if (description)
{
  script_id(91239);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-0639", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0705", "CVE-2016-2047");
  script_xref(name:"ALAS", value:"2016-701");

  script_name(english:"Amazon Linux AMI : mysql56 (ALAS-2016-701)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A double-free flaw was found in the way OpenSSL parsed certain
malformed DSA (Digital Signature Algorithm) private keys. An attacker
could create specially crafted DSA private keys that, when processed
by an application compiled against OpenSSL, could cause the
application to crash. (CVE-2016-0705)

The ssl_verify_server_cert function in sql-common/client.c in Oracle
MySQL 5.6.29 and earlier does not properly verify that the server
hostname matches a domain name in the subject's Common Name (CN) or
subjectAltName field of the X.509 certificate, which allows
man-in-the-middle attackers to spoof SSL servers via a '/CN=' string
in a field in a certificate, as demonstrated by
'/OU=/CN=bar.com/CN=foo.com'. (CVE-2016-2047)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows
remote attackers to affect confidentiality, integrity, and
availability via vectors related to Pluggable Authentication.
(CVE-2016-0639)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows
local users to affect availability via vectors related to FTS.
(CVE-2016-0647)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows
local users to affect integrity and availability via vectors related
to Federated. (CVE-2016-0642)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows
local users to affect confidentiality via vectors related to DML.
(CVE-2016-0643)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows
local users to affect availability via vectors related to Security:
Privileges. (CVE-2016-0666)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows
local users to affect availability via vectors related to PS.
(CVE-2016-0648)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows
local users to affect availability via vectors related to InnoDB.
(CVE-2016-0655)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-701.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
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
if (rpm_check(release:"ALA", reference:"mysql56-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-bench-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-common-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-debuginfo-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-devel-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-devel-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-errmsg-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-libs-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-server-5.6.30-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-test-5.6.30-1.15.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql56 / mysql56-bench / mysql56-common / mysql56-debuginfo / etc");
}
