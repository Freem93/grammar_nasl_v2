#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-691.
#

include("compat.inc");

if (description)
{
  script_id(90633);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-8629", "CVE-2015-8630", "CVE-2015-8631");
  script_xref(name:"ALAS", value:"2016-691");

  script_name(english:"Amazon Linux AMI : krb5 (ALAS-2016-691)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds read flaw was found in the kadmind service of MIT
Kerberos. An authenticated attacker could send a maliciously crafted
message to force kadmind to read beyond the end of allocated memory,
and write the memory contents to the KDC database if the attacker has
write permission, leading to information disclosure. (CVE-2015-8629)

A NULL pointer dereference flaw was found in the procedure used by the
MIT Kerberos kadmind service to store policies: the
kadm5_create_principal_3() and kadm5_modify_principal() function did
not ensure that a policy was given when KADM5_POLICY was set. An
authenticated attacker with permissions to modify the database could
use this flaw to add or modify a principal with a policy set to NULL,
causing the kadmind service to crash. (CVE-2015-8630)

A memory leak flaw was found in the krb5_unparse_name() function of
the MIT Kerberos kadmind service. An authenticated attacker could
repeatedly send specially crafted requests to the server, which could
cause the server to consume large amounts of memory resources,
ultimately leading to a denial of service due to memory exhaustion.
(CVE-2015-8631)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-691.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update krb5' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");
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
if (rpm_check(release:"ALA", reference:"krb5-debuginfo-1.13.2-12.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-devel-1.13.2-12.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-libs-1.13.2-12.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-pkinit-openssl-1.13.2-12.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-server-1.13.2-12.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-server-ldap-1.13.2-12.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-workstation-1.13.2-12.40.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit-openssl / etc");
}
