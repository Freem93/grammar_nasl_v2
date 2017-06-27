#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0917. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76698);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1544", "CVE-2014-1545");
  script_bugtraq_id(64944, 65332, 65335, 66356, 67975, 68816);
  script_osvdb_id(102170, 102876, 102877, 104708, 107912, 109430);
  script_xref(name:"RHSA", value:"2014:0917");

  script_name(english:"RHEL 6 : nss and nspr (RHSA-2014:0917)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nspr packages that fix multiple security issues,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A race condition was found in the way NSS verified certain
certificates. A remote attacker could use this flaw to crash an
application using NSS or, possibly, execute arbitrary code with the
privileges of the user running that application. (CVE-2014-1544)

A flaw was found in the way TLS False Start was implemented in NSS. An
attacker could use this flaw to potentially return unencrypted
information from the server. (CVE-2013-1740)

A race condition was found in the way NSS implemented session ticket
handling as specified by RFC 5077. An attacker could use this flaw to
crash an application using NSS or, in rare cases, execute arbitrary
code with the privileges of the user running that application.
(CVE-2014-1490)

It was found that NSS accepted weak Diffie-Hellman Key exchange (DHKE)
parameters. This could possibly lead to weak encryption being used in
communication between the client and the server. (CVE-2014-1491)

An out-of-bounds write flaw was found in NSPR. A remote attacker could
potentially use this flaw to crash an application using NSPR or,
possibly, execute arbitrary code with the privileges of the user
running that application. This NSPR flaw was not exposed to web
content in any shipped version of Firefox. (CVE-2014-1545)

It was found that the implementation of Internationalizing Domain
Names in Applications (IDNA) hostname matching in NSS did not follow
the RFC 6125 recommendations. This could lead to certain invalid
certificates with international characters to be accepted as valid.
(CVE-2014-1492)

Red Hat would like to thank the Mozilla project for reporting the
CVE-2014-1544, CVE-2014-1490, CVE-2014-1491, and CVE-2014-1545 issues.
Upstream acknowledges Tyson Smith and Jesse Schwartzentruber as the
original reporters of CVE-2014-1544, Brian Smith as the original
reporter of CVE-2014-1490, Antoine Delignat-Lavaud and Karthikeyan
Bhargavan as the original reporters of CVE-2014-1491, and Abhishek
Arya as the original reporter of CVE-2014-1545.

In addition, the nss package has been upgraded to upstream version
3.16.1, and the nspr package has been upgraded to upstream version
4.10.6. These updated packages provide a number of bug fixes and
enhancements over the previous versions. (BZ#1112136, BZ#1112135)

Users of NSS and NSPR are advised to upgrade to these updated
packages, which correct these issues and add these enhancements. After
installing this update, applications using NSS or NSPR must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1740.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1490.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0917.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0917";
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
  if (rpm_check(release:"RHEL6", reference:"nspr-4.10.6-1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nspr-debuginfo-4.10.6-1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nspr-devel-4.10.6-1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-debuginfo-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-devel-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-pkcs11-devel-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-sysinit-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-sysinit-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-sysinit-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-tools-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-tools-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-tools-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-3.16.1-1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-debuginfo-3.16.1-1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-devel-3.16.1-1.el6_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / nss / nss-debuginfo / etc");
  }
}
