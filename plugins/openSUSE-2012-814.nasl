#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-814.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74822);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-5534", "CVE-2012-5854");

  script_name(english:"openSUSE Security Update : weechat (openSUSE-SU-2012:1580-1)");
  script_summary(english:"Check for the openSUSE-2012-814 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - added weechat-fix-hook_process-shell-injection.patch
    which fixes a shell injection vulnerability in the
    hook_process function (bnc#790217, CVE-2012-5534)

  - added
    weechat-fix-buffer-overflow-in-irc-color-decoding.patch
    which fixes a heap-based overflow when decoding IRC
    colors in strings (bnc#789146, CVE-2012-5854)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-11/msg00087.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790217"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected weechat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-aspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-aspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:weechat-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
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

if ( rpm_check(release:"SUSE12.1", reference:"weechat-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-aspell-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-aspell-debuginfo-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-debuginfo-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-debugsource-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-devel-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-lang-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-lua-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-lua-debuginfo-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-perl-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-perl-debuginfo-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-python-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-python-debuginfo-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-ruby-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-ruby-debuginfo-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-tcl-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"weechat-tcl-debuginfo-0.3.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-aspell-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-aspell-debuginfo-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-debuginfo-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-debugsource-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-devel-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-guile-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-guile-debuginfo-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-lang-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-lua-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-lua-debuginfo-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-perl-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-perl-debuginfo-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-python-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-python-debuginfo-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-ruby-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-ruby-debuginfo-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-tcl-0.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"weechat-tcl-debuginfo-0.3.8-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "weechat / weechat-aspell / weechat-aspell-debuginfo / etc");
}
