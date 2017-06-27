#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-338.
#

include("compat.inc");

if (description)
{
  script_id(78281);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2013-4122");
  script_xref(name:"ALAS", value:"2014-338");

  script_name(english:"Amazon Linux AMI : cyrus-sasl (ALAS-2014-338)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Cyrus SASL 2.1.23, 2.1.26, and earlier does not properly handle when a
NULL value is returned upon an error by the crypt function as
implemented in glibc 2.17 and later, which allows remote attackers to
cause a denial of service (thread crash and consumption) via (1) an
invalid salt or, when FIPS-140 is enabled, a (2) DES or (3) MD5
encrypted password, which triggers a NULL pointer dereference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-338.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update cyrus-sasl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
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
if (rpm_check(release:"ALA", reference:"cyrus-sasl-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-debuginfo-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-devel-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-gssapi-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-ldap-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-lib-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-md5-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-ntlm-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-plain-2.1.23-13.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-sasl-sql-2.1.23-13.14.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-sasl / cyrus-sasl-debuginfo / cyrus-sasl-devel / etc");
}
