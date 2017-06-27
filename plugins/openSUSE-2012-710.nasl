#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-710.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74780);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-3479");

  script_name(english:"openSUSE Security Update : emacs and depending packages (openSUSE-SU-2012:1348-1)");
  script_summary(english:"Check for the openSUSE-2012-710 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues for emacs, emacs-w3, gnuplot
and ddskk: emacs :

  - Add fix for bnc#775993 which disable arbitrary lisp code
    execution when 'enable-local-variables' is set to
    ':safe' (CVE-2012-3479)

  - Add fix for bnc#780653 to allow emacs to parse tar
    archives with PAX extended headers

  - This update also upgrades emacs to version 24.1 :

  - Support for Gtk+3.0, GnuTLS, ImageMagick, libxml2, and
    SELinux

  - Support for wide integer (62 bits) in lisp even on
    32-bit machines.

  - The --unibyte, --multibyte, --no-multibyte, and
    --no-unibyte command line arguments, and the
    EMACS_UNIBYTE environment variable, no longer have any
    effect.

  - And many more changes see /usr/share/emacs/24.1/etc/NEWS

  - Remove obsolete patches

  - Refresh some others patches

emacs-w3 :

  - (condition-case ...) and (eval-when (compile) ...) will
    not work together

gnuplot :

  - Resolve the former problem by using texlive-texinfo to
    enforce installing required fonts as well as required
    tools for TL 2012

  - add more texlive 2012 requirements

  - Make it build with latest TeXLive 2012 with new package
    layout 

  - Convert gnuplot.el to new backtick lisp scheme for emacs
    24.1

ddskk :

  - Update to ddskk-14.4 and skkdic-20110529

  - Take some patches from Debian as well add some own
    patches

  - Drop superfluous patches"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-10/msg00057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780653"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected emacs and depending packages packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ddskk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-w3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnuplot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnuplot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnuplot-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:skkdic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:skkdic-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"ddskk-20121010_14.4-283.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-24.2-15.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-debuginfo-24.2-15.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-debugsource-24.2-15.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-el-24.2-15.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-info-24.2-15.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-nox-24.2-15.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-w3-cvs-808.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"emacs-x11-24.2-15.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnuplot-4.6.0-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnuplot-debuginfo-4.6.0-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnuplot-debugsource-4.6.0-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"skkdic-20121010_14.4-283.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"skkdic-extra-20121010_14.4-283.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ddskk / skkdic / skkdic-extra / emacs-w3 / emacs / emacs-debuginfo / etc");
}
