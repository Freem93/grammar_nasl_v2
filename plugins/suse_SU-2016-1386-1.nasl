#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1386-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91318);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/04/18 13:37:18 $");

  script_cve_id("CVE-2015-8325", "CVE-2016-1908", "CVE-2016-3115");
  script_osvdb_id(132941, 135714, 137226);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssh (SUSE-SU-2016:1386-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for OpenSSH fixes three security issues.

These security issues were fixed :

  - CVE-2016-3115: Sanitise input for xauth(1) (bsc#970632)

  - CVE-2016-1908: Prevent X11 SECURITY circumvention when
    forwarding X11 connections (bsc#962313)

  - CVE-2015-8325: Ignore PAM environment when using login
    (bsc#975865)

These non-security issues were fixed :

  - Fix help output of sftp (bsc#945493)

  - Restarting openssh with openssh-fips installed was not
    working correctly (bsc#945484)

  - Fix crashes when /proc is not available in the chroot
    (bsc#947458)

  - Correctly parse GSSAPI KEX algorithms (bsc#961368)

  - More verbose FIPS mode/CC related documentation in
    README.FIPS (bsc#965576, bsc#960414)

  - Fix PRNG re-seeding (bsc#960414, bsc#729190)

  - Disable DH parameters under 2048 bits by default and
    allow lowering the limit back to the RFC 4419 specified
    minimum through an option (bsc#932483, bsc#948902)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/729190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8325.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1908.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3115.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161386-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4af37229"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-818=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-818=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-818=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-818=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-askpass-gnome-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-askpass-gnome-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-debugsource-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-fips-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-helpers-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-helpers-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-askpass-gnome-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-askpass-gnome-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-debugsource-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-fips-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-helpers-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-helpers-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssh-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssh-askpass-gnome-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssh-askpass-gnome-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssh-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssh-debugsource-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssh-helpers-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssh-helpers-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssh-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssh-askpass-gnome-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssh-askpass-gnome-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssh-debuginfo-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssh-debugsource-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssh-helpers-6.6p1-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssh-helpers-debuginfo-6.6p1-42.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
