#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1077-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84261);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-1545", "CVE-2015-1546");
  script_bugtraq_id(72519);
  script_osvdb_id(118031, 118032);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openldap2 (SUSE-SU-2015:1077-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"openldap2 was updated to fix two security issues and one non-security
bug.

The following vulnerabilities were fixed :

  - A remote attacker could cause a denial of service
    through a NULL pointer dereference and crash via an
    empty attribute list in a deref control in a search
    request. (bnc#916897 CVE-2015-1545)

  - A remote attacker could cause a denial of service
    (crash) via a crafted search query with a matched values
    control. (bnc#916914 CVE-2015-1546)

The following non-security issue was fixed :

  - Prevent connection-0 (internal connection) from showing
    up in the monitor backend (bnc#905959)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1546.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151077-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1e6cb51"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-273=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-273=1

SUSE Linux Enterprise Module for Legacy Software 12 :

zypper in -t patch SUSE-SLE-Module-Legacy-12-2015-273=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-273=1

12 :

zypper in -t patch SUSE-SLE-SAP-12-2015-273=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-meta-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libldap-2_4-2-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libldap-2_4-2-32bit-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libldap-2_4-2-debuginfo-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libldap-2_4-2-debuginfo-32bit-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-back-meta-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-back-meta-debuginfo-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-client-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-client-debuginfo-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-client-debugsource-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-debuginfo-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openldap2-debugsource-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libldap-2_4-2-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libldap-2_4-2-debuginfo-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libldap-2_4-2-debuginfo-32bit-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openldap2-client-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openldap2-client-debuginfo-2.4.39-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openldap2-client-debugsource-2.4.39-16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap2");
}
