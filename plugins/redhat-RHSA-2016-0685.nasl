#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0685. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90749);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2016-1978", "CVE-2016-1979");
  script_osvdb_id(135604, 135718);
  script_xref(name:"RHSA", value:"2016:0685");

  script_name(english:"RHEL 7 : nss, nspr, nss-softokn, and nss-util (RHSA-2016:0685)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nss, nspr, nss-softokn, and nss-util is now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. The nss-util packages provide utilities for use
with the Network Security Services (NSS) libraries. Netscape Portable
Runtime (NSPR) provides platform independence for non-GUI operating
system facilities.

The following packages have been upgraded to a newer upstream version:
nss (3.21.0), nss-util (3.21.0), nspr (4.11.0). (BZ#1310581,
BZ#1303021, BZ# 1299872)

Security Fix(es) :

* A use-after-free flaw was found in the way NSS handled DHE
(Diffie-Hellman key exchange) and ECDHE (Elliptic Curve
Diffie-Hellman key exchange) handshake messages. A remote attacker
could send a specially crafted handshake message that, when parsed by
an application linked against NSS, would cause that application to
crash or, under certain special conditions, execute arbitrary code
using the permissions of the user running the application.
(CVE-2016-1978)

* A use-after-free flaw was found in the way NSS processed certain DER
(Distinguished Encoding Rules) encoded cryptographic keys. An attacker
could use this flaw to create a specially crafted DER encoded
certificate which, when parsed by an application compiled against the
NSS library, could cause that application to crash, or execute
arbitrary code using the permissions of the user running the
application. (CVE-2016-1979)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Eric Rescorla as the original reporter
of CVE-2016-1978; and Tim Taubert as the original reporter of
CVE-2016-1979.

Bug Fix(es) :

* The nss-softokn package has been updated to be compatible with NSS
3.21. (BZ#1326221)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1978.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0685.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0685";
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
  if (rpm_check(release:"RHEL7", reference:"nspr-4.11.0-1.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nspr-debuginfo-4.11.0-1.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nspr-devel-4.11.0-1.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-debuginfo-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-devel-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-pkcs11-devel-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-3.16.2.3-14.2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-debuginfo-3.16.2.3-14.2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-devel-3.16.2.3-14.2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-3.16.2.3-14.2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-devel-3.16.2.3-14.2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-sysinit-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-sysinit-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-tools-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-tools-3.21.0-9.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-3.21.0-2.2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-debuginfo-3.21.0-2.2.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-devel-3.21.0-2.2.el7_2")) flag++;


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
