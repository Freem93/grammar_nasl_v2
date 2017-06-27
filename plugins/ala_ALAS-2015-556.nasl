#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-556.
#

include("compat.inc");

if (description)
{
  script_id(84592);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_xref(name:"ALAS", value:"2015-556");
  script_xref(name:"RHSA", value:"2015:1194");

  script_name(english:"Amazon Linux AMI : postgresql8 (ALAS-2015-556)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A double-free flaw was found in the connection handling. An
unauthenticated attacker could exploit this flaw to crash the
PostgreSQL back end by disconnecting at approximately the same time as
the authentication time out is triggered. (CVE-2015-3165)

It was discovered that PostgreSQL did not properly check the return
values of certain standard library functions. If the system is in a
state that would cause the standard library functions to fail, for
example memory exhaustion, an authenticated user could exploit this
flaw to disclose partial memory contents or cause the GSSAPI
authentication to use an incorrect keytab file. (CVE-2015-3166)

It was discovered that the pgcrypto module could return different
error messages when decrypting certain data with an incorrect key.
This can help an authenticated user to launch a possible cryptographic
attack, although no suitable attack is currently known.
(CVE-2015-3167)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-556.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql8' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
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
if (rpm_check(release:"ALA", reference:"postgresql8-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-contrib-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-debuginfo-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-devel-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-docs-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-libs-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plperl-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plpython-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-pltcl-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-server-8.4.20-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-test-8.4.20-3.50.amzn1")) flag++;

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
