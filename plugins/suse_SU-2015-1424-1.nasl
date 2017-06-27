#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1424-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85624);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2013-2207", "CVE-2014-8121", "CVE-2015-1781");
  script_bugtraq_id(61960, 73038, 74255);
  script_osvdb_id(98105, 119253, 121105);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : glibc (SUSE-SU-2015:1424-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc provides fixes for security and non-security
issues.

These security issues have been fixed :

  - CVE-2015-1781: Buffer length after padding in
    resolv/nss_dns/dns-host.c. (bsc#927080)

  - CVE-2013-2207: pt_chown did not properly check
    permissions for tty files, which allowed local users to
    change the permission on the files and obtain access to
    arbitrary pseudo-terminals by leveraging a FUSE file
    system. (bsc#830257)

  - CVE-2014-8121: DB_LOOKUP in the Name Service Switch
    (NSS) did not properly check if a file is open, which
    allowed remote attackers to cause a denial of service
    (infinite loop) by performing a look-up while the
    database is iterated over the database, which triggers
    the file pointer to be reset. (bsc#918187)

  - Fix read past end of pattern in fnmatch. (bsc#920338)

These non-security issues have been fixed :

  - Fix locking in _IO_flush_all_lockp() to prevent
    deadlocks in applications. (bsc#851280)

  - Record TTL also for DNS PTR queries. (bsc#928723)

  - Fix invalid free in ld.so. (bsc#932059)

  - Make PowerPC64 default to non-executable stack.
    (bsc#933770)

  - Fix floating point exceptions in some circumstances with
    exp() and friends. (bsc#933903)

  - Fix bad TEXTREL in glibc.i686. (bsc#935286)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/830257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/851280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-2207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8121.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1781.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151424-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63544965"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-glibc-12042=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-glibc-12042=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-glibc-12042=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-glibc-12042=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-glibc-12042=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-glibc-12042=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-glibc-12042=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-glibc-12042=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-glibc-12042=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-devel-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-html-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-i18ndata-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-info-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-locale-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-profile-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"nscd-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"glibc-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"glibc-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"glibc-devel-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"glibc-html-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"glibc-i18ndata-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"glibc-info-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"glibc-locale-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"glibc-profile-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"nscd-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"glibc-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"glibc-devel-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"glibc-i18ndata-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"glibc-locale-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"nscd-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"glibc-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"glibc-devel-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"glibc-i18ndata-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"glibc-locale-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"nscd-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"glibc-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"glibc-devel-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"glibc-i18ndata-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"glibc-locale-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"nscd-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"glibc-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"glibc-devel-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"glibc-i18ndata-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"glibc-locale-2.11.3-17.87.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"nscd-2.11.3-17.87.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
