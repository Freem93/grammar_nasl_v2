#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-575.
#

include("compat.inc");

if (description)
{
  script_id(85230);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/05 14:41:22 $");

  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");
  script_xref(name:"ALAS", value:"2015-575");
  script_xref(name:"RHSA", value:"2015:1457");

  script_name(english:"Amazon Linux AMI : gnutls (ALAS-2015-575)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that GnuTLS did not check activation and expiration dates
of CA certificates. This could cause an application using GnuTLS to
incorrectly accept a certificate as valid when its issuing CA is
already expired. (CVE-2014-8155)

It was found that GnuTLS did not verify whether a hashing algorithm
listed in a signature matched the hashing algorithm listed in the
certificate. An attacker could create a certificate that used a
different hashing algorithm than it claimed, possibly causing GnuTLS
to use an insecure, disallowed hashing algorithm during certificate
verification. (CVE-2015-0282)

It was discovered that GnuTLS did not check if all sections of X.509
certificates indicate the same signature algorithm. This flaw, in
combination with a different flaw, could possibly lead to a bypass of
the certificate signature check. (CVE-2015-0294)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-575.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update gnutls' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/05");
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
if (rpm_check(release:"ALA", reference:"gnutls-2.8.5-18.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gnutls-debuginfo-2.8.5-18.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gnutls-devel-2.8.5-18.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gnutls-guile-2.8.5-18.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gnutls-utils-2.8.5-18.14.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-debuginfo / gnutls-devel / gnutls-guile / etc");
}
