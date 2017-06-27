#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-536.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99958);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/03 13:42:52 $");

  script_cve_id("CVE-2017-8073");

  script_name(english:"openSUSE Security Update : weechat (openSUSE-2017-536)");
  script_summary(english:"Check for the openSUSE-2017-536 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for weechat fixes one security issues :

  - CVE-2017-8073: WeeChat allowed a remote crash by sending
    a filename via DCC to the IRC plugin. This occurs in the
    irc_ctcp_dcc_filename_without_quotes function during
    quote removal, with a buffer overflow (bsc#1036467)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036467"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected weechat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"weechat-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-aspell-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-aspell-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-debugsource-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-devel-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-guile-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-guile-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-lang-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-lua-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-lua-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-perl-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-perl-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-python-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-python-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-ruby-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-ruby-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-tcl-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"weechat-tcl-debuginfo-1.5-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "weechat / weechat-aspell / weechat-aspell-debuginfo / etc");
}
