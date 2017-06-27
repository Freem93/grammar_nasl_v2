#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-492.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77136);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/12 14:41:11 $");

  script_cve_id("CVE-2014-5117");

  script_name(english:"openSUSE Security Update : tor (openSUSE-SU-2014:0975-1)");
  script_summary(english:"Check for the openSUSE-2014-492 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tor 0.2.4.23 [bnc#889688] [CVE-2014-5117] Slows down the
    risk from guard rotation and backports several important
    fixes from the Tor 0.2.5 alpha release series.

  - Major features :

  - Clients now look at the 'usecreatefast' consensus
    parameter to decide whether to use CREATE_FAST or CREATE
    cells for the first hop of their circuit. This approach
    can improve security on connections where Tor's circuit
    handshake is stronger than the available TLS connection
    security levels, but the tradeoff is more computational
    load on guard relays.

  - Make the number of entry guards configurable via a new
    NumEntryGuards consensus parameter, and the number of
    directory guards configurable via a new
    NumDirectoryGuards consensus parameter.

  - Major bugfixes :

  - Fix a bug in the bounds-checking in the 32-bit
    curve25519-donna implementation that caused incorrect
    results on 32-bit implementations when certain malformed
    inputs were used along with a small class of private
    ntor keys.

  - Minor bugfixes :

  - Warn and drop the circuit if we receive an inbound
    'relay early' cell.

  - Correct a confusing error message when trying to extend
    a circuit via the control protocol but we don't know a
    descriptor or microdescriptor for one of the specified
    relays.

  - Avoid an illegal read from stack when initializing the
    TLS module using a version of OpenSSL without all of the
    ciphers used by the v2 link handshake."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889688"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");
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

if ( rpm_check(release:"SUSE12.3", reference:"tor-0.2.4.23-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tor-debuginfo-0.2.4.23-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tor-debugsource-0.2.4.23-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-0.2.4.23-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-debuginfo-0.2.4.23-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-debugsource-0.2.4.23-5.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tor / tor-debuginfo / tor-debugsource");
}
