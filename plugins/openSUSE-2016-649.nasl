#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-649.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91403);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"openSUSE Security Update : ntp (openSUSE-2016-649)");
  script_summary(english:"Check for the openSUSE-2016-649 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ntp fixes the following issues :

  - Update to 4.2.8p7 (boo#977446) :

  - CVE-2016-1547, boo#977459: Validate crypto-NAKs, AKA:
    CRYPTO-NAK DoS.

  - CVE-2016-1548, boo#977461: Interleave-pivot

  - CVE-2016-1549, boo#977451: Sybil vulnerability:
    ephemeral association attack.

  - CVE-2016-1550, boo#977464: Improve NTP security against
    buffer comparison timing attacks.

  - CVE-2016-1551, boo#977450: Refclock impersonation
    vulnerability

  - CVE-2016-2516, boo#977452: Duplicate IPs on unconfig
    directives will cause an assertion botch in ntpd.

  - CVE-2016-2517, boo#977455: remote configuration
    trustedkey/ requestkey/controlkey values are not
    properly validated.

  - CVE-2016-2518, boo#977457: Crafted addpeer with hmode >
    7 causes array wraparound with MATCH_ASSOC.

  - CVE-2016-2519, boo#977458: ctl_getitem() return value
    not always checked.

  - integrate ntp-fork.patch

  - Improve the fixes for: CVE-2015-7704, CVE-2015-7705,
    CVE-2015-7974

  - Restrict the parser in the startup script to the first
    occurrance of 'keys' and 'controlkey' in ntp.conf
    (boo#957226).

  - Enable compile-time support for MS-SNTP
    (--enable-ntp-signd). This replaces the w32 patches in
    4.2.4 that added the authreg directive. (fate#320758).

  - Fix ntp-sntp-dst.patch (boo#975496).

  - Call /usr/sbin/sntp with full path to synchronize in
    start-ntpd. When run as cron job, /usr/sbin/ is not in
    the path, which caused the synchronization to fail.
    (boo#962318)

  - Speedup ntpq (boo#782060, ntp-speedup-ntpq.patch).

  - Sync service files with openSUSE Factory.

  - Fix the TZ offset output of sntp during DST
    (boo#951559).

  - Add ntp-fork.patch and build with threads disabled to
    allow name resolution even when running chrooted.

  - Update to 4.2.8p6 :

  - CVE-2015-8158, boo#962966: Potential Infinite Loop in
    ntpq.

  - CVE-2015-8138, boo#963002: origin: Zero Origin Timestamp
    Bypass.

  - CVE-2015-7979, boo#962784: Off-path Denial of Service
    (DoS) attack on authenticated broadcast mode.

  - CVE-2015-7978, boo#963000: Stack exhaustion in recursive
    traversal of restriction list.

  - CVE-2015-7977, boo#962970: reslist NULL pointer
    dereference.

  - CVE-2015-7976, boo#962802: ntpq saveconfig command
    allows dangerous characters in filenames.

  - CVE-2015-7975, boo#962988: nextvar() missing length
    check.

  - CVE-2015-7974, boo#962960: Skeleton Key: Missing key
    check allows impersonation between authenticated peers.

  - CVE-2015-7973, boo#962995: Deja Vu: Replay attack on
    authenticated broadcast mode.

  - CVE-2015-8140: ntpq vulnerable to replay attacks.

  - CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose
    origin.

  - CVE-2015-5300, boo#951629: Small-step/Big-step.

  - Add /var/db/ntp-kod (boo#916617).

  - Add ntp-ENOBUFS.patch to limit a warning that might
    happen quite a lot on loaded systems (boo#956773).

  - add ntp.bug2965.diff (boo#954982)

  - fixes regression in 4.2.8p4 update

  - Update to 4.2.8p4 to fix several security issues
    (boo#951608) :

  - CVE-2015-7871: NAK to the Future: Symmetric association
    authentication bypass via crypto-NAK

  - CVE-2015-7855: decodenetnum() will ASSERT botch instead
    of returning FAIL on some bogus values

  - CVE-2015-7854: Password Length Memory Corruption
    Vulnerability

  - CVE-2015-7853: Invalid length data provided by a custom
    refclock driver could cause a buffer overflow

  - CVE-2015-7852 ntpq atoascii() Memory Corruption
    Vulnerability

  - CVE-2015-7851 saveconfig Directory Traversal
    Vulnerability

  - CVE-2015-7850 remote config logfile-keyfile

  - CVE-2015-7849 trusted key use-after-free

  - CVE-2015-7848 mode 7 loop counter underrun

  - CVE-2015-7701 Slow memory leak in CRYPTO_ASSOC

  - CVE-2015-7703 configuration directives 'pidfile' and
    'driftfile' should only be allowed locally

  - CVE-2015-7704, CVE-2015-7705 Clients that receive a KoD
    should validate the origin timestamp field

  - CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 Incomplete
    autokey data packet length checks

  - obsoletes ntp-memlock.patch.

  - Add a controlkey line to /etc/ntp.conf if one does not
    already exist to allow runtime configuuration via ntpq.

  - Temporarily disable memlock to avoid problems due to
    high memory usage during name resolution (boo#946386,
    ntp-memlock.patch).

  - Use SHA1 instead of MD5 for symmetric keys (boo#905885).

  - Improve runtime configuration :

  - Read keytype from ntp.conf

  - Don't write ntp keys to syslog.

  - Fix legacy action scripts to pass on command line
    arguments.

  - Remove ntp.1.gz, it wasn't installed anymore.

  - Remove ntp-4.2.7-rh-manpages.tar.gz and only keep
    ntptime.8.gz. The rest is partially irrelevant,
    partially redundant and potentially outdated
    (boo#942587).

  - Remove 'kod' from the restrict line in ntp.conf
    (boo#944300).

  - Use ntpq instead of deprecated ntpdc in start-ntpd
    (boo#936327).

  - Add a controlkey to ntp.conf to make the above work.

  - Don't let 'keysdir' lines in ntp.conf trigger the 'keys'
    parser.

  - Disable mode 7 (ntpdc) again, now that we don't use it
    anymore.

  - Add 'addserver' as a new legacy action.

  - Fix the comment regarding addserver in ntp.conf
    (boo#910063).

  - Update to version 4.2.8p3 which incorporates all
    security fixes and most other patches we have so far
    (fate#319040). More information on:
    http://archive.ntp.org/ntp4/ChangeLog-stable

  - Disable chroot by default (boo#926510).

  - Enable ntpdc for backwards compatibility (boo#920238).

  - Security fix: ntp-keygen may generate non-random
    symmetric keys"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archive.ntp.org/ntp4/ChangeLog-stable"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=782060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=946386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"ntp-4.2.8p7-25.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ntp-debuginfo-4.2.8p7-25.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ntp-debugsource-4.2.8p7-25.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-debugsource");
}
