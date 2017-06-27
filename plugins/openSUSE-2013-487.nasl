#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-487.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75028);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/31 14:21:57 $");

  script_cve_id("CVE-2013-1982");
  script_osvdb_id(93647);

  script_name(english:"openSUSE Security Update : libXext (openSUSE-SU-2013:1009-1)");
  script_summary(english:"Check for the openSUSE-2013-487 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libXext fixes several integer overflow issues :

  -
    U_0001-integer-overflow-in-XcupGetReservedColormapEntrie
    s-C.patch,
    U_0002-integer-overflow-in-XcupStoreColors-CVE-2013-1982
    -2-.patch,
    U_0003-several-integer-overflows-in-XdbeGetVisualInfo-CV
    E-2.patch,
    U_0004-integer-overflow-in-XeviGetVisualInfo-CVE-2013-19
    82-.patch,
    U_0005-integer-overflow-in-XShapeGetRectangles-CVE-2013-
    198.patch,
    U_0006-integer-overflow-in-XSyncListSystemCounters-CVE-2
    013.patch,

  - integer overflow(s) in XcupGetReservedColormapEntries(),
    XcupStoreColors(), XdbeGetVisualInfo(),
    XeviGetVisualInfo(), XShapeGetRectangles(),
    XSyncListSystemCounters() [CVE-2013-1982] (bnc#821665,
    bnc#815451)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821665"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXext packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXext-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXext-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXext-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXext6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXext6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXext6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXext6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"libXext-debugsource-1.3.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXext-devel-1.3.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXext6-1.3.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXext6-debuginfo-1.3.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXext-devel-32bit-1.3.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXext6-32bit-1.3.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXext6-debuginfo-32bit-1.3.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXext-debugsource-1.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXext-devel-1.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXext6-1.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXext6-debuginfo-1.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXext-devel-32bit-1.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXext6-32bit-1.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXext6-debuginfo-32bit-1.3.1-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXext-debugsource / libXext-devel / libXext-devel-32bit / etc");
}
