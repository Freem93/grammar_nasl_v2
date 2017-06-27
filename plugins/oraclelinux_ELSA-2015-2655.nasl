#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2655 and 
# Oracle Linux Security Advisory ELSA-2015-2655 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87448);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/04/28 19:11:31 $");

  script_cve_id("CVE-2015-8000");
  script_osvdb_id(131837);
  script_xref(name:"RHSA", value:"2015:2655");

  script_name(english:"Oracle Linux 6 / 7 : bind (ELSA-2015-2655)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2655 :

Updated bind packages that fix one security issue are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A denial of service flaw was found in the way BIND processed certain
records with malformed class attributes. A remote attacker could use
this flaw to send a query to request a cached record with a malformed
class attribute that would cause named functioning as an authoritative
or recursive server to crash. (CVE-2015-8000)

Note: This issue affects authoritative servers as well as recursive
servers, however authoritative servers are at limited risk if they
perform authentication when making recursive queries to resolve
addresses for servers listed in NS RRSETs.

Red Hat would like to thank ISC for reporting this issue.

All bind users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, the BIND daemon (named) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-December/005646.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-December/005649.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"bind-9.8.2-0.37.rc1.el6_7.5")) flag++;
if (rpm_check(release:"EL6", reference:"bind-chroot-9.8.2-0.37.rc1.el6_7.5")) flag++;
if (rpm_check(release:"EL6", reference:"bind-devel-9.8.2-0.37.rc1.el6_7.5")) flag++;
if (rpm_check(release:"EL6", reference:"bind-libs-9.8.2-0.37.rc1.el6_7.5")) flag++;
if (rpm_check(release:"EL6", reference:"bind-sdb-9.8.2-0.37.rc1.el6_7.5")) flag++;
if (rpm_check(release:"EL6", reference:"bind-utils-9.8.2-0.37.rc1.el6_7.5")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-chroot-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-devel-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-libs-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-libs-lite-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-license-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-lite-devel-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-devel-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-libs-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-utils-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-sdb-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-sdb-chroot-9.9.4-29.el7_2.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-utils-9.9.4-29.el7_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libs / bind-libs-lite / etc");
}
