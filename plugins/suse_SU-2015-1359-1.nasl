#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1359-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85374);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-0295", "CVE-2015-1858", "CVE-2015-1859", "CVE-2015-1860");
  script_bugtraq_id(73029, 74302, 74307, 74309, 74310);
  script_osvdb_id(119072, 120574, 120575, 120576);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libqt4 (SUSE-SU-2015:1359-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The libqt4 library was updated to fix several security and non
security issues.

The following vulnerabilities were fixed :

  - bsc#921999: CVE-2015-0295: division by zero when
    processing malformed BMP files

  - bsc#927806: CVE-2015-1858: segmentation fault in BMP Qt
    Image Format Handling

  - bsc#927807: CVE-2015-1859: segmentation fault in ICO Qt
    Image Format Handling

  - bsc#927808: CVE-2015-1860: segmentation fault in GIF Qt
    Image Format Handling

The following non-secuirty issues were fixed :

  - bsc#929688: Critical Problem in Qt Network Stack

  - bsc#847880: kde/qt rendering error in qemu cirrus i586

  - Update use-freetype-default.diff to use same method as
    with libqt5-qtbase package: Qt itself already does
    runtime check whether subpixel rendering is available,
    but only when FT_CONFIG_OPTION_SUBPIXEL_RENDERING is
    defined. Thus it is enough to only remove that condition

  - The -devel subpackage requires Mesa-devel, not only at
    build time

  - Fixed compilation on SLE_11_SP3 by making it build
    against Mesa-devel on that system

  - Replace patch l-qclipboard_fix_recursive.patch with
    qtcore-4.8.5-qeventdispatcher-recursive.patch. The later
    one seems to work better and really resolves the issue
    in LibreOffice

  - Added kde4_qt_plugin_path.patch, so kde4 plugins are
    magically found/known outside kde4 enviroment/session

  - added _constraints. building took up to 7GB of disk
    space on s390x, and more than 6GB on x86_64

  - Add 3 patches for Qt bugs to make LibreOffice KDE4 file
    picker work properly again :

  - Add glib-honor-ExcludeSocketNotifiers-flag.diff
    (QTBUG-37380)

  - Add l-qclipboard_fix_recursive.patch (QTBUG-34614)

  - Add l-qclipboard_delay.patch (QTBUG-38585)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/847880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0295.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1859.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1860.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151359-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?376c25ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-380=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-380=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-380=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-380=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-devel-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-devel-doc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-qt3support-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-x11-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-debugsource-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-devel-doc-debuginfo-4.8.6-4.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-devel-doc-debugsource-4.8.6-4.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-qt3support-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-qt3support-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-sql-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-sql-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-sql-mysql-4.8.6-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-sql-sqlite-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-sql-sqlite-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-x11-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-x11-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qt4-x11-tools-4.8.6-4.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qt4-x11-tools-debuginfo-4.8.6-4.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-qt3support-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-qt3support-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-sql-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-sql-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-x11-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqt4-x11-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-debugsource-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-qt3support-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-qt3support-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-qt3support-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-mysql-32bit-4.8.6-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-mysql-4.8.6-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-postgresql-32bit-4.8.6-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-postgresql-4.8.6-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-sqlite-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-sqlite-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-sqlite-debuginfo-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-unixODBC-32bit-4.8.6-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-sql-unixODBC-4.8.6-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-x11-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-x11-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-x11-debuginfo-32bit-4.8.6-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libqt4-x11-debuginfo-4.8.6-4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt4");
}
