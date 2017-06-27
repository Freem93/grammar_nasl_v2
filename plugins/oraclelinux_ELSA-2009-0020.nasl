#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0020 and 
# Oracle Linux Security Advisory ELSA-2009-0020 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67792);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0025", "CVE-2009-0046", "CVE-2009-0047", "CVE-2009-0048", "CVE-2009-0049", "CVE-2009-0124", "CVE-2009-0125", "CVE-2009-0127", "CVE-2009-0128", "CVE-2009-0130");
  script_bugtraq_id(33151);
  script_xref(name:"RHSA", value:"2009:0020");

  script_name(english:"Oracle Linux 3 / 4 / 5 : bind (ELSA-2009-0020)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0020 :

Updated Bind packages to correct a security issue are now available
for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

BIND (Berkeley Internet Name Domain) is an implementation of the DNS
(Domain Name System) protocols.

A flaw was discovered in the way BIND checked the return value of the
OpenSSL DSA_do_verify function. On systems using DNSSEC, a malicious
zone could present a malformed DSA certificate and bypass proper
certificate validation, allowing spoofing attacks. (CVE-2009-0025)

For users of Red Hat Enterprise Linux 3 this update also addresses a
bug which can cause BIND to occasionally exit with an assertion
failure.

All BIND users are advised to upgrade to the updated package, which
contains a backported patch to resolve this issue. After installing
the update, BIND daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000856.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000857.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:caching-nameserver");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-chroot-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-chroot-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-devel-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-devel-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-libs-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-libs-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-utils-9.2.4-23.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-utils-9.2.4-23.el3")) flag++;

if (rpm_check(release:"EL4", reference:"bind-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"bind-chroot-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"bind-devel-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"bind-libs-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"bind-utils-9.2.4-30.el4_7.1")) flag++;

if (rpm_check(release:"EL5", reference:"bind-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bind-chroot-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bind-devel-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bind-libbind-devel-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bind-libs-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bind-sdb-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bind-utils-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"caching-nameserver-9.3.4-6.0.3.P1.el5_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
}
