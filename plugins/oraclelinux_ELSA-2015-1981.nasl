#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1981 and 
# Oracle Linux Security Advisory ELSA-2015-1981 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86742);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2016/12/07 21:08:16 $");

  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");
  script_osvdb_id(129797, 129798, 129799);
  script_xref(name:"RHSA", value:"2015:1981");

  script_name(english:"Oracle Linux 6 / 7 : nspr / nss / nss-util (ELSA-2015-1981)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1981 :

Updated nss, nss-util, and nspr packages that fix three security
issues are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A use-after-poison flaw and a heap-based buffer overflow flaw were
found in the way NSS parsed certain ASN.1 structures. An attacker
could use these flaws to cause NSS to crash or execute arbitrary code
with the permissions of the user running an application compiled
against the NSS library. (CVE-2015-7181, CVE-2015-7182)

A heap-based buffer overflow was found in NSPR. An attacker could use
this flaw to cause NSPR to crash or execute arbitrary code with the
permissions of the user running an application compiled against the
NSPR library. (CVE-2015-7183)

Note: Applications using NSPR's PL_ARENA_ALLOCATE, PR_ARENA_ALLOCATE,
PL_ARENA_GROW, or PR_ARENA_GROW macros need to be rebuild against the
fixed nspr packages to completely resolve the CVE-2015-7183 issue.
This erratum includes nss and nss-utils packages rebuilt against the
fixed nspr version.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Tyson Smith, David Keeler and Ryan
Sleevi as the original reporter.

All nss, nss-util and nspr users are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005490.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005494.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr, nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
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
if (rpm_check(release:"EL6", reference:"nspr-4.10.8-2.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nspr-devel-4.10.8-2.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nss-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nss-devel-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nss-pkcs11-devel-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nss-sysinit-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nss-tools-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-3.19.1-2.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"nss-util-devel-3.19.1-2.el6_7")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nspr-4.10.8-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nspr-devel-4.10.8-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-3.19.1-7.0.1.el7_1.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-devel-3.19.1-7.0.1.el7_1.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.19.1-7.0.1.el7_1.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-sysinit-3.19.1-7.0.1.el7_1.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-tools-3.19.1-7.0.1.el7_1.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-util-3.19.1-4.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-util-devel-3.19.1-4.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / etc");
}
