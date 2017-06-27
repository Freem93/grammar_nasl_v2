#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-398.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75376);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/22 14:14:59 $");

  script_cve_id("CVE-2014-0160");

  script_name(english:"openSUSE Security Update : tor (openSUSE-SU-2014:0719-1) (Heartbleed)");
  script_summary(english:"Check for the openSUSE-2014-398 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - tor 0.2.4.22 [bnc#878486] Tor was updated to the
    recommended version of the 0.2.4.x series.

  - major features in 0.2.4.x :

  - improved client resilience

  - support better link encryption with forward secrecy

  - new NTor circuit handshake

  - change relay queue for circuit create requests from
    size-based limit to time-based limit

  - many bug fixes and minor features

  - changes contained in 0.2.4.22: Backports numerous
    high-priority fixes. These include blocking all
    authority signing keys that may have been affected by
    the OpenSSL 'heartbleed' bug, choosing a far more secure
    set of TLS ciphersuites by default, closing a couple of
    memory leaks that could be used to run a target relay
    out of RAM.

  - Major features (security)

  - Block authority signing keys that were used on
    authorities vulnerable to the 'heartbleed' bug in
    OpenSSL (CVE-2014-0160).

  - Major bugfixes (security, OOM) :

  - Fix a memory leak that could occur if a microdescriptor
    parse fails during the tokenizing step.

  - Major bugfixes (TLS cipher selection) :

  - The relay ciphersuite list is now generated
    automatically based on uniform criteria, and includes
    all OpenSSL ciphersuites with acceptable strength and
    forward secrecy.

  - Relays now trust themselves to have a better view than
    clients of which TLS ciphersuites are better than
    others.

  - Clients now try to advertise the same list of
    ciphersuites as Firefox 28.

  - includes changes from 0.2.4.21: Further improves
    security against potential adversaries who find breaking
    1024-bit crypto doable, and backports several stability
    and robustness patches from the 0.2.5 branch.

  - Major features (client security) :

  - When we choose a path for a 3-hop circuit, make sure it
    contains at least one relay that supports the NTor
    circuit extension handshake. Otherwise, there is a
    chance that we're building a circuit that's worth
    attacking by an adversary who finds breaking 1024-bit
    crypto doable, and that chance changes the game theory.

  - Major bugfixes :

  - Do not treat streams that fail with reason
    END_STREAM_REASON_INTERNAL as indicating a definite
    circuit failure, since it could also indicate an
    ENETUNREACH connection error

  - includes changes from 0.2.4.20 :

  - Do not allow OpenSSL engines to replace the PRNG, even
    when HardwareAccel is set.

  - Fix assertion failure when AutomapHostsOnResolve yields
    an IPv6 address.

  - Avoid launching spurious extra circuits when a stream is
    pending.

  - packaging changes :

  - remove init script shadowing systemd unit

  - general cleanup

  - Add tor-fw-helper for UPnP port forwarding; not used by
    default

  - fix logrotate on systemd-only setups without init
    scripts, work tor-0.2.2.37-logrotate.patch to
    tor-0.2.4.x-logrotate.patch

  - verify source tarball signature"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878486"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.3", reference:"tor-0.2.4.22-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tor-debuginfo-0.2.4.22-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tor-debugsource-0.2.4.22-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-0.2.4.22-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-debuginfo-0.2.4.22-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-debugsource-0.2.4.22-5.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tor / tor-debuginfo / tor-debugsource");
}
