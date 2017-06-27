#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0004. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35316);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0046", "CVE-2009-0047", "CVE-2009-0048", "CVE-2009-0049", "CVE-2009-0124", "CVE-2009-0125", "CVE-2009-0127", "CVE-2009-0128", "CVE-2009-0130");
  script_xref(name:"RHSA", value:"2009:0004");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : openssl (RHSA-2009:0004)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that correct a security issue are now
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
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20090107.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0004.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(20, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl095a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl097a");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(2\.1|3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0004";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-0.9.6b-49")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"openssl-0.9.6b-49")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-devel-0.9.6b-49")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-perl-0.9.6b-49")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl095a-0.9.5a-34")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl096-0.9.6-34")) flag++;


  if (rpm_check(release:"RHEL3", reference:"openssl-0.9.7a-33.25")) flag++;

  if (rpm_check(release:"RHEL3", reference:"openssl-devel-0.9.7a-33.25")) flag++;

  if (rpm_check(release:"RHEL3", reference:"openssl-perl-0.9.7a-33.25")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openssl096b-0.9.6b-16.49")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"openssl096b-0.9.6b-16.49")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"openssl096b-0.9.6b-16.49")) flag++;


  if (rpm_check(release:"RHEL4", reference:"openssl-0.9.7a-43.17.el4_7.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openssl-devel-0.9.7a-43.17.el4_7.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openssl-perl-0.9.7a-43.17.el4_7.2")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openssl096b-0.9.6b-22.46.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"openssl096b-0.9.6b-22.46.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"openssl096b-0.9.6b-22.46.el4_7")) flag++;


  if (rpm_check(release:"RHEL5", reference:"openssl-0.9.8b-10.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openssl-devel-0.9.8b-10.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssl-perl-0.9.8b-10.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssl-perl-0.9.8b-10.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssl-perl-0.9.8b-10.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssl097a-0.9.7a-9.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssl097a-0.9.7a-9.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssl097a-0.9.7a-9.el5_2.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl095a / openssl096 / etc");
  }
}
