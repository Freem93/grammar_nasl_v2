#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1287-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83597);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2009-5029", "CVE-2010-4756", "CVE-2011-1089", "CVE-2012-0864", "CVE-2012-3480", "CVE-2013-1914");
  script_bugtraq_id(46740, 50898, 52201, 54982, 58839);
  script_osvdb_id(74883, 75008, 77508, 79705, 80719, 84710, 92038);

  script_name(english:"SUSE SLES10 Security Update : glibc (SUSE-SU-2013:1287-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This collective update for the GNU C library (glibc) provides the
following fixes and enhancements :

Security issues fixed :

  - Fix stack overflow in getaddrinfo with many results.
    (bnc#813121, CVE-2013-1914)

  - Fixed another stack overflow in getaddrinfo with many
    results (bnc#828637)

  - Fix buffer overflow in glob. (bnc#691365)
    (CVE-2010-4756)

  - Fix array overflow in floating point parser [bnc#775690]
    (CVE-2012-3480)

  - Fix strtod integer/buffer overflows [bnc#775690]
    (CVE-2012-3480) Make addmntent return errors also for
    cached streams. [bnc #676178, CVE-2011-1089]

  - Fix overflows in vfprintf. [bnc #770891, CVE 2012-3406]

  - Add vfprintf-nargs.diff for possible format string
    overflow. [bnc #747768, CVE-2012-0864]

  - Check values from file header in __tzfile_read. [bnc
    #735850, CVE-2009-5029]

Also several bugs were fixed :

  - Fix locking in _IO_cleanup. (bnc#796982)

  - Fix memory leak in execve. (bnc#805899) Fix nscd
    timestamps in logging (bnc#783196)

  - Fix perl script error message (bnc#774467)

  - Fall back to localhost if no nameserver defined
    (bnc#818630)

  - Fix incomplete results from nscd. [bnc #753756]

  - Fix a deadlock in dlsym in case the symbol isn't found,
    for multithreaded programs. [bnc #760216]

  - Fix problem with TLS and dlopen. [#732110]

  - Backported regex fix for skipping of valid EUC-JP
    matches [bnc#743689]

  - Fixed false regex match on incomplete chars in EUC-JP
    [bnc#743689]

  - Add glibc-pmap-timeout.diff in order to fix useless
    connection attempts to NFS servers. [bnc #661460]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=17c15337eaf4f28f28cdc9f9d3d731ec
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c6953c2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-5029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4756.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0864.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/661460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/676178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/691365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/732110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/735850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/743689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/747768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/753756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/760216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/770891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/774467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/775690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/783196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/796982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/818630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828637"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131287-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16a241e5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glibc packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:UR");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"glibc-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"glibc-profile-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"glibc-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"glibc-devel-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"glibc-locale-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"glibc-profile-32bit-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"glibc-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"glibc-devel-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"glibc-html-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"glibc-i18ndata-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"glibc-info-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"glibc-locale-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"glibc-profile-2.4-31.77.102.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"nscd-2.4-31.77.102.1")) flag++;


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
