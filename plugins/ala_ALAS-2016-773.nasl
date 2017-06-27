#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-773.
#

include("compat.inc");

if (description)
{
  script_id(95893);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/16 14:23:20 $");

  script_cve_id("CVE-2016-4992", "CVE-2016-5405", "CVE-2016-5416");
  script_xref(name:"ALAS", value:"2016-773");

  script_name(english:"Amazon Linux AMI : 389-ds-base (ALAS-2016-773)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-5405 389-ds-base: Password verification vulnerable to timing
attack

It was found that 389 Directory Server was vulnerable to a remote
password disclosure via timing attack. A remote attacker could
possibly use this flaw to retrieve directory server password after
many tries.

CVE-2016-5416 389-ds-base: ACI readable by anonymous user

It was found that 389 Directory Server was vulnerable to a flaw in
which the default ACI (Access Control Instructions) could be read by
an anonymous user. This could lead to leakage of sensitive
information.

CVE-2016-4992 389-ds-base: Information disclosure via repeated use of
LDAP ADD operation

An information disclosure flaw was found in 389 Directory Server. A
user with no access to objects in certain LDAP sub-tree could send
LDAP ADD operations with a specific object name. The error message
returned to the user was different based on whether the target object
existed or not."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-773.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update 389-ds-base' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");
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
if (rpm_check(release:"ALA", reference:"389-ds-base-1.3.5.10-11.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-debuginfo-1.3.5.10-11.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-devel-1.3.5.10-11.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-libs-1.3.5.10-11.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-snmp-1.3.5.10-11.49.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
