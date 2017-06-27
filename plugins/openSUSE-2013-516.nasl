#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-516.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75052);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-1981", "CVE-2013-1997", "CVE-2013-2004");
  script_bugtraq_id(60120, 60122, 60146);
  script_osvdb_id(93648, 93653, 93661, 93690);

  script_name(english:"openSUSE Security Update : libX11 (openSUSE-SU-2013:1047-1)");
  script_summary(english:"Check for the openSUSE-2013-516 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libX11 fixes several security issues. 

  -
    U_0001-integer-overflow-in-_XQueryFont-on-32-bit-platfor
    ms-.patch,
    U_0002-integer-overflow-in-_XF86BigfontQueryFont-CVE-201
    3-1.patch,
    U_0003-integer-overflow-in-XListFontsWithInfo-CVE-2013-1
    981.patch,
    U_0004-integer-overflow-in-XGetMotionEvents-CVE-2013-198
    1-4.patch,
    U_0005-integer-overflow-in-XListHosts-CVE-2013-1981-5-13
    .patch,
    U_0006-Integer-overflows-in-stringSectionSize-cause-buff
    er-.patch,
    U_0007-integer-overflow-in-ReadInFile-in-Xrm.c-CVE-2013-
    198.patch,
    U_0008-integer-truncation-in-_XimParseStringFile-CVE-201
    3-1.patch,
    U_0009-integer-overflows-in-TransFileName-CVE-2013-1981-
    9-1.patch,
    U_0010-integer-overflow-in-XGetWindowProperty-CVE-2013-1
    981.patch,
    U_0011-integer-overflow-in-XGetImage-CVE-2013-1981-11-13
    .patch,
    U_0012-integer-overflow-in-XGetPointerMapping-XGetKeyboa
    rdM.patch,
    U_0013-integer-overflow-in-XGetModifierMapping-CVE-2013-
    198.patch

  - integer overflow in various functions, integer
    truncation in _XimParseStringFile() [CVE-2013-1981]
    (bnc#821664, bnc#815451)

  -
    U_0001-unvalidated-lengths-in-XAllocColorCells-CVE-2013-
    199.patch,
    U_0002-unvalidated-index-in-_XkbReadGetDeviceInfoReply-C
    VE-.patch,
    U_0003-unvalidated-indexes-in-_XkbReadGeomShapes-CVE-201
    3-1.patch,
    U_0004-unvalidated-indexes-in-_XkbReadGetGeometryReply-C
    VE-.patch,
    U_0005-unvalidated-index-in-_XkbReadKeySyms-CVE-2013-199
    7-5.patch,
    U_0006-unvalidated-index-in-_XkbReadKeyActions-CVE-2013-
    199.patch,
    U_0007-unvalidated-index-in-_XkbReadKeyBehaviors-CVE-201
    3-1.patch,
    U_0008-unvalidated-index-in-_XkbReadModifierMap-CVE-2013
    -19.patch,
    U_0009-unvalidated-index-in-_XkbReadExplicitComponents-C
    VE-.patch,
    U_0010-unvalidated-index-in-_XkbReadVirtualModMap-CVE-20
    13-.patch,
    U_0011-unvalidated-index-length-in-_XkbReadGetNamesReply
    -CV.patch,
    U_0012-unvalidated-length-in-_XimXGetReadData-CVE-2013-1
    997.patch,
    U_0013-Avoid-overflows-in-XListFonts-CVE-2013-1997-13-15
    .patch,
    U_0014-Avoid-overflows-in-XGetFontPath-CVE-2013-1997-14-
    15.patch,
    U_0015-Avoid-overflows-in-XListExtensions-CVE-2013-1997-
    15-.patch

  - unvalidated index/length in various functions; Avoid
    overflows in XListFonts(), XGetFontPath(),
    XListExtensions() [CVE-2013-1997] (bnc##821664,
    bnc#815451)

  -
    U_0001-Unbounded-recursion-in-GetDatabase-when-parsing-i
    ncl.patch,
    U_0002-Unbounded-recursion-in-_XimParseStringFile-when-p
    ars.patch

  - Unbounded recursion in GetDatabase(),
    _XimParseStringFile when parsing include files
    [CVE-2013-2004] (bnc##821664, bnc#815451)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00171.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821664"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libX11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libX11-6-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libX11-6-debuginfo-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libX11-data-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libX11-debugsource-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libX11-devel-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libX11-xcb1-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libX11-xcb1-debuginfo-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libX11-6-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libX11-6-debuginfo-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libX11-devel-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libX11-6-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libX11-6-debuginfo-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libX11-data-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libX11-debugsource-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libX11-devel-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libX11-xcb1-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libX11-xcb1-debuginfo-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libX11-6-32bit-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libX11-6-debuginfo-32bit-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libX11-devel-32bit-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.5.0-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-32bit-1.5.0-4.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11-6 / libX11-6-32bit / libX11-6-debuginfo / etc");
}
