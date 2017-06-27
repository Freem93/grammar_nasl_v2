#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1090 and 
# Oracle Linux Security Advisory ELSA-2012-1090 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68580);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2012-0441");
  script_bugtraq_id(53798);
  script_osvdb_id(82675);
  script_xref(name:"RHSA", value:"2012:1090");

  script_name(english:"Oracle Linux 5 : nspr / nss (ELSA-2012-1090)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:1090 :

Updated nss and nspr packages that fix two security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way the ASN.1 (Abstract Syntax Notation One)
decoder in NSS handled zero length items. This flaw could cause the
decoder to incorrectly skip or replace certain items with a default
value, or could cause an application to crash if, for example, it
received a specially crafted OCSP (Online Certificate Status Protocol)
response. (CVE-2012-0441)

It was found that a Certificate Authority (CA) issued a subordinate CA
certificate to its customer, that could be used to issue certificates
for any name. This update renders the subordinate CA certificate as
untrusted. (BZ#798533)

Note: The BZ#798533 fix only applies to applications using the NSS
Builtin Object Token. It does not render the certificates untrusted
for applications that use the NSS library, but do not use the NSS
Builtin Object Token.

In addition, the nspr package has been upgraded to upstream version
4.9.1, and the nss package has been upgraded to upstream version
3.13.5. These updates provide a number of bug fixes and enhancements
over the previous versions. (BZ#834220, BZ#834219)

All NSS and NSPR users should upgrade to these updated packages, which
correct these issues and add these enhancements. After installing the
update, applications using NSS and NSPR must be restarted for the
changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002942.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"nspr-4.9.1-4.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-devel-4.9.1-4.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"nss-3.13.5-4.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.13.5-4.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.13.5-4.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.13.5-4.0.1.el5_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / nss-tools");
}
