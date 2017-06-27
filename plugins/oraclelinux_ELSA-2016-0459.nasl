#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0459 and 
# Oracle Linux Security Advisory ELSA-2016-0459 respectively.
#

include("compat.inc");

if (description)
{
  script_id(89980);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2016-1285", "CVE-2016-1286");
  script_osvdb_id(135663, 135664);
  script_xref(name:"RHSA", value:"2016:0459");

  script_name(english:"Oracle Linux 5 / 6 / 7 : bind (ELSA-2016-0459)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0459 :

Updated bind packages that fix two security issues are now available
for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A denial of service flaw was found in the way BIND parsed signature
records for DNAME records. By sending a specially crafted query, a
remote attacker could use this flaw to cause named to crash.
(CVE-2016-1286)

A denial of service flaw was found in the way BIND processed certain
control channel input. A remote attacker able to send a malformed
packet to the control channel could use this flaw to cause named to
crash. (CVE-2016-1285)

Red Hat would like to thank ISC for reporting these issues.

All bind users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the BIND daemon (named) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005863.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005864.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005865.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libbind-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");
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
if (rpm_check(release:"EL5", reference:"bind-9.3.6-25.P1.el5_11.8")) flag++;
if (rpm_check(release:"EL5", reference:"bind-chroot-9.3.6-25.P1.el5_11.8")) flag++;
if (rpm_check(release:"EL5", reference:"bind-devel-9.3.6-25.P1.el5_11.8")) flag++;
if (rpm_check(release:"EL5", reference:"bind-libbind-devel-9.3.6-25.P1.el5_11.8")) flag++;
if (rpm_check(release:"EL5", reference:"bind-libs-9.3.6-25.P1.el5_11.8")) flag++;
if (rpm_check(release:"EL5", reference:"bind-sdb-9.3.6-25.P1.el5_11.8")) flag++;
if (rpm_check(release:"EL5", reference:"bind-utils-9.3.6-25.P1.el5_11.8")) flag++;
if (rpm_check(release:"EL5", reference:"caching-nameserver-9.3.6-25.P1.el5_11.8")) flag++;

if (rpm_check(release:"EL6", reference:"bind-9.8.2-0.37.rc1.el6_7.7")) flag++;
if (rpm_check(release:"EL6", reference:"bind-chroot-9.8.2-0.37.rc1.el6_7.7")) flag++;
if (rpm_check(release:"EL6", reference:"bind-devel-9.8.2-0.37.rc1.el6_7.7")) flag++;
if (rpm_check(release:"EL6", reference:"bind-libs-9.8.2-0.37.rc1.el6_7.7")) flag++;
if (rpm_check(release:"EL6", reference:"bind-sdb-9.8.2-0.37.rc1.el6_7.7")) flag++;
if (rpm_check(release:"EL6", reference:"bind-utils-9.8.2-0.37.rc1.el6_7.7")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-chroot-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-devel-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-libs-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-libs-lite-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-license-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-lite-devel-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-devel-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-libs-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-pkcs11-utils-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-sdb-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-sdb-chroot-9.9.4-29.el7_2.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bind-utils-9.9.4-29.el7_2.3")) flag++;


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
