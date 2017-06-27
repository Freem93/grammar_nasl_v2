#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-443.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74691);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1951", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1967");
  script_osvdb_id(83995, 83996, 83997, 83998, 83999, 84000, 84001, 84002, 84003, 84004, 84005, 84006, 84007, 84010, 84013);

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2012:0917-1)");
  script_summary(english:"Check for the openSUSE-2012-443 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to version 14.0 (bnc#771583)

  - MFSA 2012-42/CVE-2012-1949/CVE-2012-1948 Miscellaneous
    memory safety hazards

  - MFSA
    2012-44/CVE-2012-1951/CVE-2012-1954/CVE-2012-1953/CVE-20
    12-1952 Gecko memory corruption

  - MFSA 2012-45/CVE-2012-1955 (bmo#757376) Spoofing issue
    with location

  - MFSA 2012-47/CVE-2012-1957 (bmo#750096) Improper
    filtering of JavaScript in HTML feed-view

  - MFSA 2012-48/CVE-2012-1958 (bmo#750820) use-after-free
    in nsGlobalWindow::PageHidden

  - MFSA 2012-49/CVE-2012-1959 (bmo#754044, bmo#737559)
    Same-compartment Security Wrappers can be bypassed

  - MFSA 2012-50/CVE-2012-1960 (bmo#761014) Out of bounds
    read in QCMS

  - MFSA 2012-51/CVE-2012-1961 (bmo#761655) X-Frame-Options
    header ignored when duplicated

  - MFSA 2012-52/CVE-2012-1962 (bmo#764296)
    JSDependentString::undepend string conversion results in
    memory corruption

  - MFSA 2012-53/CVE-2012-1963 (bmo#767778) Content Security
    Policy 1.0 implementation errors cause data leakage

  - MFSA 2012-56/CVE-2012-1967 (bmo#758344) Code execution
    through javascript: URLs

  - relicensed to MPL-2.0

  - update Enigmail to 1.4.3

  - no crashreport on %arm, fixing build"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771583"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/23");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-debuginfo-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.4.3+14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.4.3+14.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-buildsymbols-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-debuginfo-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-debugsource-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-devel-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-devel-debuginfo-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-translations-common-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"MozillaThunderbird-translations-other-14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"enigmail-1.4.3+14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"enigmail-debuginfo-1.4.3+14.0-24.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.4.3+14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.4.3+14.0-33.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-buildsymbols-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-debuginfo-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-debugsource-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-devel-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-devel-debuginfo-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-translations-common-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"MozillaThunderbird-translations-other-14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"enigmail-1.4.3+14.0-33.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"enigmail-debuginfo-1.4.3+14.0-33.26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
