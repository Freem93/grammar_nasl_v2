#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-242.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74941);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-2503");

  script_name(english:"openSUSE Security Update : privoxy (openSUSE-2013-242)");
  script_summary(english:"Check for the openSUSE-2013-242 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"privoxy was updated to 3.0.21 stable fo fix CVE-2013-2503 (bnc#809123)

  - changes in 3.0.21

  - On POSIX-like platforms, network sockets with file
    descriptor values above FD_SETSIZE are properly
    rejected. Previously they could cause memory corruption
    in configurations that allowed the limit to be reached.

  - Proxy authentication headers are removed unless the new
    directive enable-proxy-authentication-forwarding is
    used. Forwarding the headers potentionally allows
    malicious sites to trick the user into providing them
    with login information. Reported by Chris John Riley.

  - Compiles on OS/2 again now that unistd.h is only
    included on platforms that have it.

  - The show-status page shows the
    FEATURE_STRPTIME_SANITY_CHECKS status.

  - A couple of assert()s that could theoretically
    dereference NULL pointers in debug builds have been
    relocated.

  - Added an LSB info block to the generic start script.
    Based on a patch from Natxo Asenjo.

  - The max-client-connections default has been changed to
    128 which should be more than enough for most setups.

  - Block rover.ebay./ar.*\&adtype= instead of
    '/.*\&adtype=' which caused too man false positives.
    Reported by u302320 in #360284, additional feedback from
    Adam Piggott.

  - Unblock '.advrider.com/' and '/.*ADVrider'. Anonymously
    reported in #3603636.

  - Stop blocking '/js/slider\.js'. Reported by Adam Piggott
    in #3606635 and _lvm in #2791160.

  - Added an iframes filter.

  - The whole GPLv2 text is included in the user manual now,
    so Privoxy can serve it itself and the user can read it
    without having to wade through GPLv3 ads first.

  - Properly numbered and underlined a couple of section
    titles in the config that where previously overlooked
    due to a flaw in the conversion script. Reported by Ralf
    Jungblut.

  - Improved the support instruction to hopefully make it
    harder to unintentionally provide insufficient
    information when requesting support. Previously it
    wasn't obvious that the information we need in bug
    reports is usually also required in support requests.

  - Removed documentation about packages that haven't been
    provided in years.

  - Only log the test number when not running in verbose
    mode The position of the test is rarely relevant and it
    previously

  - for full list of changes see ChangeLog file shipped
    together with this package"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809123"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected privoxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"privoxy-3.0.21-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"privoxy-debuginfo-3.0.21-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"privoxy-debugsource-3.0.21-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"privoxy-3.0.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"privoxy-debuginfo-3.0.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"privoxy-debugsource-3.0.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"privoxy-3.0.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"privoxy-debuginfo-3.0.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"privoxy-debugsource-3.0.21-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "privoxy");
}
