#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1151-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(99978);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id("CVE-2017-6507");
  script_osvdb_id(154291);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : apparmor (SUSE-SU-2017:1151-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apparmor provides the following fixes: This security
issue was fixed :

  - CVE-2017-6507: Preserve unknown profiles when reloading
    apparmor.service (bsc#1029696) These non-security issues
    were fixed :

  - Add tunables/kernelvars abstraction. (bsc#1031529)

  - Update flags of ntpd profile. (bsc#1022610)

  - Force AppArmor to start after /var/lib mounts.
    (bsc#1016259)

  - Update mlmmj profiles. (bsc#1000201)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6507.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171151-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f943271"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-669=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-669=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-669=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-669=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-669=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-669=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-669=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-669=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apparmor-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apparmor-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apparmor-parser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libapparmor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libapparmor1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pam_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pam_apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apparmor-debugsource-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apparmor-parser-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apparmor-parser-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libapparmor1-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libapparmor1-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pam_apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pam_apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libapparmor1-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libapparmor1-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pam_apparmor-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pam_apparmor-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"apache2-mod_apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"apache2-mod_apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"apparmor-debugsource-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"apparmor-parser-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"apparmor-parser-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libapparmor1-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libapparmor1-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"perl-apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"perl-apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libapparmor1-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libapparmor1-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"apparmor-debugsource-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"apparmor-parser-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"apparmor-parser-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libapparmor1-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libapparmor1-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libapparmor1-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libapparmor1-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pam_apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pam_apparmor-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pam_apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pam_apparmor-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"perl-apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"perl-apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"apparmor-debugsource-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"apparmor-parser-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"apparmor-parser-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libapparmor1-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libapparmor1-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libapparmor1-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libapparmor1-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-debuginfo-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"pam_apparmor-debuginfo-32bit-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-apparmor-2.8.2-54.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-apparmor-debuginfo-2.8.2-54.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apparmor");
}
