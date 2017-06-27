#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1311-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91248);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2015-5194", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158");
  script_osvdb_id(116071, 126663, 126665, 126666, 129298, 129299, 129300, 129301, 129302, 129303, 129304, 129305, 129306, 129307, 129308, 129309, 129310, 129311, 129315, 133378, 133382, 133383, 133384, 133385, 133386, 133387, 133388, 133389, 133390, 133391, 133414);
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"SUSE SLES11 Security Update : ntp (SUSE-SU-2016:1311-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This network time protocol server ntp was updated to 4.2.8p6 to fix
the following issues :

Also yast2-ntp-client was updated to match some sntp syntax changes.
(bsc#937837)

Major functional changes :

  - The 'sntp' commandline tool changed its option handling
    in a major way.

  - 'controlkey 1' is added during update to ntp.conf to
    allow sntp to work.

  - The local clock is being disabled during update.

  - ntpd is no longer running chrooted.

Other functional changes :

  - ntp-signd is installed.

  - 'enable mode7' can be added to the configuration to
    allow ntdpc to work as compatibility mode option.

  - 'kod' was removed from the default restrictions.

  - SHA1 keys are used by default instead of MD5 keys.

These security issues were fixed :

  - CVE-2015-5219: An endless loop due to incorrect
    precision to double conversion (bsc#943216).

  - CVE-2015-8158: Fixed potential infinite loop in ntpq
    (bsc#962966).

  - CVE-2015-8138: Zero Origin Timestamp Bypass
    (bsc#963002).

  - CVE-2015-7979: Off-path Denial of Service (DoS) attack
    on authenticated broadcast mode (bsc#962784).

  - CVE-2015-7978: Stack exhaustion in recursive traversal
    of restriction list (bsc#963000).

  - CVE-2015-7977: reslist NULL pointer dereference
    (bsc#962970).

  - CVE-2015-7976: ntpq saveconfig command allows dangerous
    characters in filenames (bsc#962802).

  - CVE-2015-7975: nextvar() missing length check
    (bsc#962988).

  - CVE-2015-7974: Skeleton Key: Missing key check allows
    impersonation between authenticated peers (bsc#962960).

  - CVE-2015-7973: Replay attack on authenticated broadcast
    mode (bsc#962995).

  - CVE-2015-8140: ntpq vulnerable to replay attacks
    (bsc#962994).

  - CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose
    origin (bsc#962997).

  - CVE-2015-5300: MITM attacker could have forced ntpd to
    make a step larger than the panic threshold
    (bsc#951629).

  - CVE-2015-7871: NAK to the Future: Symmetric association
    authentication bypass via crypto-NAK (bsc#951608).

  - CVE-2015-7855: decodenetnum() will ASSERT botch instead
    of returning FAIL on some bogus values (bsc#951608).

  - CVE-2015-7854: Password Length Memory Corruption
    Vulnerability (bsc#951608).

  - CVE-2015-7853: Invalid length data provided by a custom
    refclock driver could cause a buffer overflow
    (bsc#951608).

  - CVE-2015-7852: ntpq atoascii() Memory Corruption
    Vulnerability (bsc#951608).

  - CVE-2015-7851: saveconfig Directory Traversal
    Vulnerability (bsc#951608).

  - CVE-2015-7850: remote config logfile-keyfile
    (bsc#951608).

  - CVE-2015-7849: trusted key use-after-free (bsc#951608).

  - CVE-2015-7848: mode 7 loop counter underrun
    (bsc#951608).

  - CVE-2015-7701: Slow memory leak in CRYPTO_ASSOC
    (bsc#951608).

  - CVE-2015-7703: configuration directives 'pidfile' and
    'driftfile' should only be allowed locally (bsc#951608).

  - CVE-2015-7704, CVE-2015-7705: Clients that receive a KoD
    should validate the origin timestamp field (bsc#951608).

  - CVE-2015-7691, CVE-2015-7692, CVE-2015-7702: Incomplete
    autokey data packet length checks (bsc#951608).

These non-security issues were fixed :

  - fate#320758 bsc#975981: Enable compile-time support for
    MS-SNTP (--enable-ntp-signd). This replaces the w32
    patches in 4.2.4 that added the authreg directive.

  - bsc#962318: Call /usr/sbin/sntp with full path to
    synchronize in start-ntpd. When run as cron job,
    /usr/sbin/ is not in the path, which caused the
    synchronization to fail.

  - bsc#782060: Speedup ntpq.

  - bsc#916617: Add /var/db/ntp-kod.

  - bsc#956773: Add ntp-ENOBUFS.patch to limit a warning
    that might happen quite a lot on loaded systems.

  - bsc#951559,bsc#975496: Fix the TZ offset output of sntp
    during DST.

  - Add ntp-fork.patch and build with threads disabled to
    allow name resolution even when running chrooted.

  - Add a controlkey line to /etc/ntp.conf if one does not
    already exist to allow runtime configuuration via ntpq.

  - bsc#946386: Temporarily disable memlock to avoid
    problems due to high memory usage during name
    resolution.

  - bsc#905885: Use SHA1 instead of MD5 for symmetric keys.

  - Improve runtime configuration :

  - Read keytype from ntp.conf

  - Don't write ntp keys to syslog.

  - Fix legacy action scripts to pass on command line
    arguments.

  - bsc#944300: Remove 'kod' from the restrict line in
    ntp.conf.

  - bsc#936327: Use ntpq instead of deprecated ntpdc in
    start-ntpd.

  - Don't let 'keysdir' lines in ntp.conf trigger the 'keys'
    parser.

  - Disable mode 7 (ntpdc) again, now that we don't use it
    anymore.

  - Add 'addserver' as a new legacy action.

  - bsc#910063: Fix the comment regarding addserver in
    ntp.conf.

  - bsc#926510: Disable chroot by default.

  - bsc#920238: Enable ntpdc for backwards compatibility.

  - bsc#784760: Remove local clock from default
    configuration.

  - bsc#942441/fate#319496: Require perl-Socket6.

  - Improve runtime configuration :

  - Read keytype from ntp.conf

  - Don't write ntp keys to syslog.

  - bsc#920183: Allow -4 and -6 address qualifiers in
    'server' directives.

  - Use upstream ntp-wait, because our version is
    incompatible with the new ntpq command line syntax.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/782060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/784760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5219.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5300.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7701.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7703.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7850.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7853.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7854.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7973.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7975.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7976.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7977.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7978.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8140.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8158.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161311-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d95af488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5 :

zypper in -t patch sleclo50sp3-ntp-12561=1

SUSE Manager Proxy 2.1 :

zypper in -t patch slemap21-ntp-12561=1

SUSE Manager 2.1 :

zypper in -t patch sleman21-ntp-12561=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-ntp-12561=1

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-ntp-12561=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-ntp-12561=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-ntp-12561=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"ntp-4.2.8p6-41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ntp-doc-4.2.8p6-41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"ntp-4.2.8p6-41.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"ntp-doc-4.2.8p6-41.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
