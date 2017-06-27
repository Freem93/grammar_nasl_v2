#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0004 and 
# Oracle Linux Security Advisory ELSA-2009-0004 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67783);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0046", "CVE-2009-0047", "CVE-2009-0048", "CVE-2009-0049", "CVE-2009-0124", "CVE-2009-0125", "CVE-2009-0127", "CVE-2009-0128", "CVE-2009-0130");
  script_xref(name:"RHSA", value:"2009:0004");

  script_name(english:"Oracle Linux 3 / 4 / 5 : openssl (ELSA-2009-0004)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0004 :

Updated OpenSSL packages that correct a security issue are now
available for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength, general purpose, cryptography library.

The Google security team discovered a flaw in the way OpenSSL checked
the verification of certificates. An attacker in control of a
malicious server, or able to effect a 'man in the middle' attack,
could present a malformed SSL/TLS signature from a certificate chain
to a vulnerable client and bypass validation. (CVE-2008-5077)

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all running OpenSSL client applications must be
restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000851.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(20, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl096b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl097a");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/08");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl-devel-0.9.7a-33.25")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl-devel-0.9.7a-33.25")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl-perl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl-perl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl096b-0.9.6b-16.49")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl096b-0.9.6b-16.49")) flag++;

if (rpm_check(release:"EL4", reference:"openssl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"openssl-devel-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"openssl-perl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"openssl096b-0.9.6b-22.46.el4_7")) flag++;

if (rpm_check(release:"EL5", reference:"openssl-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"openssl-devel-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"openssl-perl-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"openssl097a-0.9.7a-9.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl096b / openssl097a");
}
