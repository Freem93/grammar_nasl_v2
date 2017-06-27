#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-94.
#

include("compat.inc");

if (description)
{
  script_id(69701);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-2143", "CVE-2012-2655");
  script_xref(name:"ALAS", value:"2012-94");
  script_xref(name:"RHSA", value:"2012:1037");

  script_name(english:"Amazon Linux AMI : postgresql8 (ALAS-2012-94)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way the crypt() password hashing function from
the optional PostgreSQL pgcrypto contrib module performed password
transformation when used with the DES algorithm. If the password
string to be hashed contained the 0x80 byte value, the remainder of
the string was ignored when calculating the hash, significantly
reducing the password strength. This made brute-force guessing more
efficient as the whole password was not required to gain access to
protected resources. (CVE-2012-2143)

Note: With this update, the rest of the string is properly included in
the DES hash; therefore, any previously stored password values that
are affected by this issue will no longer match. In such cases, it
will be necessary for those stored password hashes to be updated.

A denial of service flaw was found in the way the PostgreSQL server
performed a user privileges check when applying SECURITY DEFINER or
SET attributes to a procedural language's (such as PL/Perl or
PL/Python) call handler function. A non-superuser database owner could
use this flaw to cause the PostgreSQL server to crash due to infinite
recursion. (CVE-2012-2655)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-94.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql8' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/05");
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
if (rpm_check(release:"ALA", reference:"postgresql8-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-contrib-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-debuginfo-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-devel-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-docs-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-libs-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plperl-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plpython-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-pltcl-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-server-8.4.12-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-test-8.4.12-1.35.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql8 / postgresql8-contrib / postgresql8-debuginfo / etc");
}
