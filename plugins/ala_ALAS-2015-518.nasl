#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-518.
#

include("compat.inc");

if (description)
{
  script_id(83269);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/02 13:41:58 $");

  script_cve_id("CVE-2014-5352", "CVE-2014-5353", "CVE-2014-5355", "CVE-2014-9421", "CVE-2014-9422");
  script_xref(name:"ALAS", value:"2015-518");
  script_xref(name:"RHSA", value:"2015:0794");

  script_name(english:"Amazon Linux AMI : krb5 (ALAS-2015-518)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-free flaw was found in the way the MIT Kerberos
libgssapi_krb5 library processed valid context deletion tokens. An
attacker able to make an application using the GSS-API library
(libgssapi) could call the gss_process_context_token() function and
use this flaw to crash that application. (CVE-2014-5352)

If kadmind were used with an LDAP back end for the KDC database, a
remote, authenticated attacker who has the permissions to set the
password policy could crash kadmind by attempting to use a named
ticket policy object as a password policy for a principal.
(CVE-2014-5353)

It was found that the krb5_read_message() function of MIT Kerberos did
not correctly sanitize input, and could create invalid krb5_data
objects. A remote, unauthenticated attacker could use this flaw to
crash a Kerberos child process via a specially crafted request.
(CVE-2014-5355)

A double-free flaw was found in the way MIT Kerberos handled invalid
External Data Representation (XDR) data. An authenticated user could
use this flaw to crash the MIT Kerberos administration server
(kadmind), or other applications using Kerberos libraries, via
specially crafted XDR packets. (CVE-2014-9421)

It was found that the MIT Kerberos administration server (kadmind)
incorrectly accepted certain authentication requests for two-component
server principal names. A remote attacker able to acquire a key with a
particularly named principal (such as 'kad/x') could use this flaw to
impersonate any user to kadmind, and perform administrative actions as
that user. (CVE-2014-9422)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-518.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update krb5' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"krb5-debuginfo-1.10.3-37.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-devel-1.10.3-37.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-libs-1.10.3-37.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-pkinit-openssl-1.10.3-37.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-server-1.10.3-37.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-server-ldap-1.10.3-37.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"krb5-workstation-1.10.3-37.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit-openssl / etc");
}
