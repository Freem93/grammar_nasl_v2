#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-532.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74723);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-3455");

  script_name(english:"openSUSE Security Update : koffice (openSUSE-SU-2012:1060-1)");
  script_summary(english:"Check for the openSUSE-2012-532 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"This update fixes a buffer overflow in MS Word ODF import filter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774533"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected koffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-karbon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kexi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kformula-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kplato-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kpresenter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-krita-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kspread-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kthesaurus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kthesaurus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice2-kword-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"koffice2-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-debugsource-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-devel-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-karbon-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-karbon-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kexi-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kexi-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kformula-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kformula-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kplato-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kplato-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kpresenter-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kpresenter-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-krita-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-krita-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kspread-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kspread-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kthesaurus-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kthesaurus-debuginfo-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kword-2.3.1-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"koffice2-kword-debuginfo-2.3.1-12.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "koffice");
}
