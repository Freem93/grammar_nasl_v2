#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1073. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77243);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-1492");
  script_bugtraq_id(66356);
  script_osvdb_id(104708);
  script_xref(name:"RHSA", value:"2014:1073");

  script_name(english:"RHEL 7 : nss, nss-util, nss-softokn (RHSA-2014:1073)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nss-util, and nss-softokn packages that fix one security
issue, several bugs, and add various enhancements are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSLv3,
TLS, and other security standards.

It was found that the implementation of Internationalizing Domain
Names in Applications (IDNA) hostname matching in NSS did not follow
the RFC 6125 recommendations. This could lead to certain invalid
certificates with international characters to be accepted as valid.
(CVE-2014-1492)

In addition, the nss, nss-util, and nss-softokn packages have been
upgraded to upstream version 3.16.2, which provides a number of bug
fixes and enhancements over the previous versions. (BZ#1124659)

Users of NSS are advised to upgrade to these updated packages, which
correct these issues and add these enhancements. After installing this
update, applications using NSS must be restarted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1073.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/19");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1073";
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
  if (rpm_check(release:"RHEL7", reference:"nss-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-debuginfo-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-devel-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-pkcs11-devel-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-softokn-3.16.2-1.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-softokn-debuginfo-3.16.2-1.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-softokn-devel-3.16.2-1.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-3.16.2-1.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-devel-3.16.2-1.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-sysinit-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-sysinit-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-tools-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-tools-3.16.2-2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-util-3.16.2-1.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-util-debuginfo-3.16.2-1.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nss-util-devel-3.16.2-1.el7_0")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-softokn / etc");
  }
}
