#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1307 and 
# Oracle Linux Security Advisory ELSA-2014-1307 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77952);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_osvdb_id(112036);
  script_xref(name:"RHSA", value:"2014:1307");

  script_name(english:"Oracle Linux 5 / 6 / 7 : nss (ELSA-2014-1307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1307 :

Updated nss packages that fix one security issue are now available for
Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way NSS parsed ASN.1 (Abstract Syntax Notation
One) input from certain RSA signatures. A remote attacker could use
this flaw to forge RSA certificates by providing a specially crafted
signature to an application using NSS. (CVE-2014-1568)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Antoine Delignat-Lavaud and Intel Product
Security Incident Response Team as the original reporters.

All NSS users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, applications using NSS must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-September/004487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-September/004490.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-September/004491.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"nss-3.16.1-4.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.16.1-4.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.16.1-4.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.16.1-4.el5_11")) flag++;

if (rpm_check(release:"EL6", reference:"nss-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-devel-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-pkcs11-devel-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-softokn-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-softokn-devel-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-softokn-freebl-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-softokn-freebl-devel-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-sysinit-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-tools-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-3.16.1-2.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-devel-3.16.1-2.el6_5")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-3.16.2-7.0.1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-devel-3.16.2-7.0.1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.16.2-7.0.1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-softokn-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-softokn-devel-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-softokn-freebl-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-sysinit-3.16.2-7.0.1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-tools-3.16.2-7.0.1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-util-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-util-devel-3.16.2-2.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-devel / nss-pkcs11-devel / nss-softokn / etc");
}
