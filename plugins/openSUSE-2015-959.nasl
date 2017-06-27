#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-959.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87631);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2014-0191", "CVE-2014-3660", "CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-2015-959)");
  script_summary(english:"Check for the openSUSE-2015-959 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 2.9.3

  - full changelog: http://www.xmlsoft.org/news.html

  - fixed CVEs: CVE-2015-8242, CVE-2015-7500, CVE-2015-7499,
    CVE-2015-5312, CVE-2015-7497, CVE-2015-7498,
    CVE-2015-8035, CVE-2015-7942, CVE-2015-1819,
    CVE-2015-7941, CVE-2014-3660, CVE-2014-0191,
    CVE-2015-8241, CVE-2015-8317

  - fixed bugs: [bsc#928193], [bsc#951734], [bsc#951735],
    [bsc#954429], [bsc#956018], [bsc#956021], [bsc#956260],
    [bsc#957105], [bsc#957106], [bsc#957107], [bsc#957109],
    [bsc#957110]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.xmlsoft.org/news.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957110"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libxml2-2-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libxml2-2-debuginfo-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libxml2-debugsource-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libxml2-devel-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libxml2-tools-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libxml2-tools-debuginfo-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-libxml2-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-libxml2-debuginfo-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-libxml2-debugsource-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.3-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-2-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-2-debuginfo-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-debugsource-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-devel-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-tools-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-tools-debuginfo-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libxml2-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libxml2-debuginfo-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libxml2-debugsource-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.9.3-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.3-7.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2-2 / libxml2-2-32bit / libxml2-2-debuginfo / etc");
}
