#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-41.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75386);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-0979");
  script_bugtraq_id(64679);
  script_osvdb_id(101846);

  script_name(english:"openSUSE Security Update : lightdm-gtk-greeter (openSUSE-SU-2014:0071-1)");
  script_summary(english:"Check for the openSUSE-2014-41 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - add lightdm-gtk-greeter-handle-invalid-user.patch in
    order to fix a NULL pointer dereference after
    authentication of an invalid username has failed
    (bnc#857303, CVE-2014-0979)

  - add lightdm-gtk-greeter-invalid-last_session.patch fix
    segfault when last_session is an invalid session
    (lp#1161883)

  - add lightdm-gtk-greeter-fix-login.patch in order to fix
    login/unlock detection"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857303"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lightdm-gtk-greeter packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/08");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"lightdm-gtk-greeter-1.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lightdm-gtk-greeter-branding-upstream-1.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lightdm-gtk-greeter-debuginfo-1.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lightdm-gtk-greeter-debugsource-1.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lightdm-gtk-greeter-lang-1.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lightdm-gtk-greeter-1.3.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lightdm-gtk-greeter-branding-upstream-1.3.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lightdm-gtk-greeter-debuginfo-1.3.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lightdm-gtk-greeter-debugsource-1.3.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lightdm-gtk-greeter-lang-1.3.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lightdm-gtk-greeter-1.3.1-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lightdm-gtk-greeter-branding-upstream-1.3.1-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lightdm-gtk-greeter-debuginfo-1.3.1-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lightdm-gtk-greeter-debugsource-1.3.1-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lightdm-gtk-greeter-lang-1.3.1-5.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lightdm-gtk-greeter / lightdm-gtk-greeter-branding-upstream / etc");
}
