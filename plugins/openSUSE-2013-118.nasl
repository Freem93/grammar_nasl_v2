#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-118.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74889);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-5656", "CVE-2012-6076");

  script_name(english:"openSUSE Security Update : inkscape (openSUSE-SU-2013:0294-1)");
  script_summary(english:"Check for the openSUSE-2013-118 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Inkscape was updated to fix two security issues :

  - inkscape occasionaly tries to open EPS files from /tmp
    (bnc#796306, CVE-2012-6076).

  - inkscape could load XML from external hosts (bnc#794958,
    CWE-827, CVE-2012-5656)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796306"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected inkscape packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-extensions-dia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-extensions-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-extensions-fig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-extensions-gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-extensions-skencil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:inkscape-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/06");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"inkscape-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-debuginfo-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-debugsource-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-extensions-dia-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-extensions-extra-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-extensions-fig-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-extensions-gimp-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-extensions-skencil-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"inkscape-lang-0.48.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-debuginfo-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-debugsource-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-extensions-dia-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-extensions-extra-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-extensions-fig-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-extensions-gimp-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-extensions-skencil-0.48.3.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"inkscape-lang-0.48.3.1-5.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "inkscape");
}
