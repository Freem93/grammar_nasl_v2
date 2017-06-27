#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-176.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75272);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-6493");
  script_bugtraq_id(65437);

  script_name(english:"openSUSE Security Update : icedtea-web (openSUSE-SU-2014:0310-1)");
  script_summary(english:"Check for the openSUSE-2014-176 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"icedtea-web was updated to version 1.4.2 (bnc#864364), fixing various
bugs and a security issues :

  - Dialogs center on screen before becoming visible

  - Support for u45 new manifest attributes
    (Application-Name)

  - Custom applet permission policies panel in
    itweb-settings control panel

  - Plugin

  - PR1271: icedtea-web does not handle
    'javascript:'-protocol URLs

  - RH976833: Multiple applets on one page cause deadlock

  - Enabled javaconsole

  - Security Updates

  - CVE-2013-6493/RH1010958: insecure temporary file use
    flaw in LiveConnect implementation

  - Except above also :

  - Christmas splashscreen extension

  - fixed classloading deadlocks

  - cleaned code from warnings

  - pipes moved to XDG runtime dir

  - Patches changes :

  - rebased icedtea-web-1.1-moonlight-symbol-clash.patch

  - add icedtea-web-1.4.2-mkdir.patch

  - add icedtea-web-1.4.2-softkiller-link.patch

  - build with rhino support

  - use fdupes

  - run make run-netx-dist-tests in %check on openSUSE >
    13.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/18");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-1.4.2-4.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-debuginfo-1.4.2-4.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-debugsource-1.4.2-4.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-javadoc-1.4.2-4.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-1.4.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-debuginfo-1.4.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-debugsource-1.4.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-javadoc-1.4.2-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web");
}
