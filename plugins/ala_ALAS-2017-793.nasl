#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-793.
#

include("compat.inc");

if (description)
{
  script_id(97023);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/09 15:37:55 $");

  script_cve_id("CVE-2016-3119", "CVE-2016-3120");
  script_xref(name:"ALAS", value:"2017-793");
  script_xref(name:"IAVB", value:"2016-B-0115");

  script_name(english:"Amazon Linux AMI : krb5 (ALAS-2017-793)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference flaw was found in MIT Kerberos kadmind
service. An authenticated attacker with permission to modify a
principal entry could use this flaw to cause kadmind to dereference a
NULL pointer and crash by supplying an empty DB argument to the
modify_principal command, if kadmind was configured to use the LDAP
KDB module. (CVE-2016-3119)

A NULL pointer dereference flaw was found in MIT Kerberos krb5kdc
service. An authenticated attacker could use this flaw to cause
krb5kdc to dereference a NULL pointer and crash by making an S4U2Self
request, if the restrict_anonymous_to_tgt option was set to true.
(CVE-2016-3120)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-793.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update krb5' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libkadm5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"ALA", reference:"krb5-debuginfo-1.14.1-27.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-devel-1.14.1-27.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-libs-1.14.1-27.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-pkinit-openssl-1.14.1-27.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-server-1.14.1-27.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-server-ldap-1.14.1-27.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-workstation-1.14.1-27.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libkadm5-1.14.1-27.41.amzn1")) flag++;

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
