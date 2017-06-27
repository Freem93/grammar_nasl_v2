#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:800. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20050);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 18:06:54 $");

  script_cve_id("CVE-2005-0109", "CVE-2005-2969");
  script_osvdb_id(16440, 19919);
  script_xref(name:"RHSA", value:"2005:800");

  script_name(english:"RHEL 2.1 / 3 / 4 : openssl (RHSA-2005:800)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that fix various security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength general purpose cryptography library.

OpenSSL contained a software work-around for a bug in SSL handling in
Microsoft Internet Explorer version 3.0.2. This work-around is enabled
in most servers that use OpenSSL to provide support for SSL and TLS.
Yutaka Oiwa discovered that this work-around could allow an attacker,
acting as a 'man in the middle' to force an SSL connection to use SSL
2.0 rather than a stronger protocol such as SSL 3.0 or TLS 1.0. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-2969 to this issue.

A bug was also fixed in the way OpenSSL creates DSA signatures. A
cache timing attack was fixed in RHSA-2005-476 which caused OpenSSL to
do private key calculations with a fixed time window. The DSA fix for
this was not complete and the calculations are not always performed
within a fixed-window. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0109 to this
issue.

Users are advised to upgrade to these updated packages, which remove
the MISE 3.0.2 work-around and contain patches to correct these
issues.

Note: After installing this update, users are advised to either
restart all services that use OpenSSL or restart their system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2969.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-800.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl095a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:800";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-0.9.6b-40")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"openssl-0.9.6b-40")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-devel-0.9.6b-40")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-perl-0.9.6b-40")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl095a-0.9.5a-26")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl096-0.9.6-27")) flag++;

  if (rpm_check(release:"RHEL3", reference:"openssl-0.9.7a-33.17")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openssl-devel-0.9.7a-33.17")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openssl-perl-0.9.7a-33.17")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openssl096b-0.9.6b-16.22.4")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"openssl096b-0.9.6b-16.22.4")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"openssl096b-0.9.6b-16.22.4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openssl-0.9.7a-43.4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"openssl-devel-0.9.7a-43.4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"openssl-perl-0.9.7a-43.4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openssl096b-0.9.6b-22.4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"openssl096b-0.9.6b-22.4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"openssl096b-0.9.6b-22.4")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
