#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2779 and 
# Oracle Linux Security Advisory ELSA-2016-2779 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94927);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id("CVE-2016-2834", "CVE-2016-5285", "CVE-2016-8635");
  script_osvdb_id(147521, 147522);
  script_xref(name:"RHSA", value:"2016:2779");

  script_name(english:"Oracle Linux 5 / 6 / 7 : nss / nss-util (ELSA-2016-2779)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2779 :

An update for nss and nss-util is now available for Red Hat Enterprise
Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version:
nss (3.12.3), nss-util (3.12.3).

Security Fix(es) :

* Multiple buffer handling flaws were found in the way NSS handled
cryptographic data from the network. A remote attacker could use these
flaws to crash an application using NSS or, possibly, execute
arbitrary code with the permission of the user running the
application. (CVE-2016-2834)

* A NULL pointer dereference flaw was found in the way NSS handled
invalid Diffie-Hellman keys. A remote client could use this flaw to
crash a TLS/SSL server using NSS. (CVE-2016-5285)

* It was found that Diffie Hellman Client key exchange handling in NSS
was vulnerable to small subgroup confinement attack. An attacker could
use this flaw to recover private keys by confining the client DH key
to small subgroup of the desired group. (CVE-2016-8635)

Red Hat would like to thank the Mozilla project for reporting
CVE-2016-2834. The CVE-2016-8635 issue was discovered by Hubert Kario
(Red Hat). Upstream acknowledges Tyson Smith and Jed Davis as the
original reporter of CVE-2016-2834."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006520.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006521.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL5", reference:"nss-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.21.3-2.el5_11")) flag++;

if (rpm_check(release:"EL6", reference:"nss-3.21.3-2.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"nss-devel-3.21.3-2.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"nss-pkcs11-devel-3.21.3-2.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"nss-sysinit-3.21.3-2.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"nss-tools-3.21.3-2.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-3.21.3-1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-devel-3.21.3-1.el6_8")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-3.21.3-2.0.1.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-devel-3.21.3-2.0.1.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.21.3-2.0.1.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-sysinit-3.21.3-2.0.1.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-tools-3.21.3-2.0.1.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-util-3.21.3-1.1.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-util-devel-3.21.3-1.1.el7_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-devel / nss-pkcs11-devel / nss-sysinit / nss-tools / etc");
}
