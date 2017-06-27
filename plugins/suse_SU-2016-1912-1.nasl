#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1912-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93186);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2015-1798", "CVE-2015-1799", "CVE-2015-5194", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519", "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_bugtraq_id(73950, 73951);
  script_osvdb_id(116071, 120350, 120351, 126663, 126666, 129298, 129299, 129300, 129301, 129302, 129303, 129304, 129305, 129306, 129307, 129308, 129309, 129310, 129311, 129315, 133378, 133382, 133383, 133384, 133385, 133386, 133387, 133388, 133391, 133414, 137711, 137712, 137713, 137714, 137731, 137732, 137733, 137734, 137735, 139280, 139281, 139282, 139283, 139284);
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"SUSE SLES10 Security Update : ntp (SUSE-SU-2016:1912-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NTP was updated to version 4.2.8p8 to fix several security issues and
to ensure the continued maintainability of the package.

These security issues were fixed :

CVE-2016-4953: Bad authentication demobilized ephemeral associations
(bsc#982065).

CVE-2016-4954: Processing spoofed server packets (bsc#982066).

CVE-2016-4955: Autokey association reset (bsc#982067).

CVE-2016-4956: Broadcast interleave (bsc#982068).

CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).

CVE-2016-1547: Validate crypto-NAKs to prevent ACRYPTO-NAK DoS
(bsc#977459).

CVE-2016-1548: Prevent the change of time of an ntpd client or denying
service to an ntpd client by forcing it to change from basic
client/server mode to interleaved symmetric mode (bsc#977461).

CVE-2016-1549: Sybil vulnerability: ephemeral association attack
(bsc#977451).

CVE-2016-1550: Improve security against buffer comparison timing
attacks (bsc#977464).

CVE-2016-1551: Refclock impersonation vulnerability (bsc#977450)y

CVE-2016-2516: Duplicate IPs on unconfig directives could have caused
an assertion botch in ntpd (bsc#977452).

CVE-2016-2517: Remote configuration trustedkey/ requestkey/controlkey
values are not properly validated (bsc#977455).

CVE-2016-2518: Crafted addpeer with hmode > 7 causes array wraparound
with MATCH_ASSOC (bsc#977457).

CVE-2016-2519: ctl_getitem() return value not always checked
(bsc#977458).

CVE-2015-8158: Potential Infinite Loop in ntpq (bsc#962966).

CVE-2015-8138: Zero Origin Timestamp Bypass (bsc#963002).

CVE-2015-7979: Off-path Denial of Service (DoS) attack on
authenticated broadcast mode (bsc#962784).

CVE-2015-7978: Stack exhaustion in recursive traversal of restriction
list (bsc#963000).

CVE-2015-7977: reslist NULL pointer dereference (bsc#962970).

CVE-2015-7976: ntpq saveconfig command allowed dangerous characters in
filenames (bsc#962802).

CVE-2015-7975: nextvar() missing length check (bsc#962988).

CVE-2015-7974: NTP did not verify peer associations of symmetric keys
when authenticating packets, which might have allowed remote attackers
to conduct impersonation attacks via an arbitrary trusted key, aka a
'skeleton' key (bsc#962960).

CVE-2015-7973: Replay attack on authenticated broadcast mode
(bsc#962995).

CVE-2015-5300: MITM attacker can force ntpd to make a step larger than
the panic threshold (bsc#951629).

CVE-2015-5194: Crash with crafted logconfig configuration command
(bsc#943218).

CVE-2015-7871: NAK to the Future: Symmetric association authentication
bypass via crypto-NAK (bsc#952611).

CVE-2015-7855: decodenetnum() will ASSERT botch instead of returning
FAIL on some bogus values (bsc#952611).

CVE-2015-7854: Password Length Memory Corruption Vulnerability
(bsc#952611).

CVE-2015-7853: Invalid length data provided by a custom refclock
driver could cause a buffer overflow (bsc#952611).

CVE-2015-7852: ntpq atoascii() Memory Corruption Vulnerability
(bsc#952611).

CVE-2015-7851: saveconfig Directory Traversal Vulnerability
(bsc#952611).

CVE-2015-7850: Clients that receive a KoD now validate the origin
timestamp field (bsc#952611).

CVE-2015-7849: Prevent use-after-free trusted key (bsc#952611).

CVE-2015-7848: Prevent mode 7 loop counter underrun (bsc#952611).

CVE-2015-7701: Slow memory leak in CRYPTO_ASSOC (bsc#952611).

CVE-2015-7703: Configuration directives 'pidfile' and 'driftfile'
should only be allowed locally (bsc#943221).

CVE-2015-7704: Clients that receive a KoD should validate the origin
timestamp field (bsc#952611).

CVE-2015-7705: Clients that receive a KoD should validate the origin
timestamp field (bsc#952611).

CVE-2015-7691: Incomplete autokey data packet length checks
(bsc#952611).

CVE-2015-7692: Incomplete autokey data packet length checks
(bsc#952611).

CVE-2015-7702: Incomplete autokey data packet length checks
(bsc#952611).

CVE-2015-1798: The symmetric-key feature in the receive function in
ntp_proto.c in ntpd in NTP required a correct MAC only if the MAC
field has a nonzero length, which made it easier for man-in-the-middle
attackers to spoof packets by omitting the MAC (bsc#924202).

CVE-2015-1799: The symmetric-key feature in the receive function in
ntp_proto.c in ntpd in NTP performed state-variable updates upon
receiving certain invalid packets, which made it easier for
man-in-the-middle attackers to cause a denial of service
(synchronization loss) by spoofing the source IP address of a peer
(bsc#924202).

These non-security issues were fixed :

Keep the parent process alive until the daemon has finished
initialisation, to make sure that the PID file exists when the parent
returns.

bsc#979302: Change the process name of the forking DNS worker process
to avoid the impression that ntpd is started twice.

bsc#981422: Don't ignore SIGCHILD because it breaks wait().

Separate the creation of ntp.keys and key #1 in it to avoid problems
when upgrading installations that have the file, but no key #1, which
is needed e.g. by 'rcntp addserver'.

bsc#957226: Restrict the parser in the startup script to the first
occurrance of 'keys' and 'controlkey' in ntp.conf.

Enable compile-time support for MS-SNTP (--enable-ntp-signd)

bsc#975496: Fix ntp-sntp-dst.patch.

bsc#962318: Call /usr/sbin/sntp with full path to synchronize in
start-ntpd. When run as cron job, /usr/sbin/ is not in the path, which
caused the synchronization to fail.

bsc#782060: Speedup ntpq.

bsc#951559: Fix the TZ offset output of sntp during DST.

bsc#916617: Add /var/db/ntp-kod.

bsc#951351: Add ntp-ENOBUFS.patch to limit a warning that might happen
quite a lot on loaded systems.

Add ntp-fork.patch and build with threads disabled to allow name
resolution even when running chrooted.

bnc#784760: Remove local clock from default configuration.

Fix incomplete backporting of 'rcntp ntptimemset'.

bsc#936327: Use ntpq instead of deprecated ntpdc in start-ntpd.

Don't let 'keysdir' lines in ntp.conf trigger the 'keys' parser.

bsc#910063: Fix the comment regarding addserver in ntp.conf.

bsc#944300: Remove 'kod' from the restrict line in ntp.conf.

bsc#905885: Use SHA1 instead of MD5 for symmetric keys.

bsc#926510: Re-add chroot support, but mark it as deprecated and
disable it by default.

bsc#920895: Drop support for running chrooted, because it is an
ongoing source of problems and not really needed anymore, given that
ntp now drops privileges and runs under apparmor.

bsc#920183: Allow -4 and -6 address qualifiers in 'server' directives.

Use upstream ntp-wait, because our version is incompatible with the
new ntpq command line syntax.

bsc#920905: Adjust Util.pm to the Perl version on SLE11.

bsc#920238: Enable ntpdc for backwards compatibility.

bsc#920893: Don't use %exclude.

bsc#988417: Default to NTPD_FORCE_SYNC_ON_STARTUP='yes'

bsc#988565: Ignore errors when removing extra files during
uninstallation

bsc#988558: Don't blindly guess the value to use for IP_TOS

Security Issues :

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4953'>CVE
-2016-4953</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4954'>CVE
-2016-4954</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4955'>CVE
-2016-4955</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4956'>CVE
-2016-4956</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4957'>CVE
-2016-4957</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1547'>CVE
-2016-1547</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1548'>CVE
-2016-1548</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1549'>CVE
-2016-1549</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1550'>CVE
-2016-1550</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1551'>CVE
-2016-1551</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2516'>CVE
-2016-2516</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2517'>CVE
-2016-2517</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2518'>CVE
-2016-2518</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2519'>CVE
-2016-2519</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8158'>CVE
-2015-8158</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8138'>CVE
-2015-8138</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7979'>CVE
-2015-7979</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7978'>CVE
-2015-7978</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7977'>CVE
-2015-7977</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7976'>CVE
-2015-7976</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7975'>CVE
-2015-7975</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7974'>CVE
-2015-7974</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7973'>CVE
-2015-7973</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5300'>CVE
-2015-5300</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5194'>CVE
-2015-5194</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7871'>CVE
-2015-7871</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7855'>CVE
-2015-7855</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7854'>CVE
-2015-7854</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7853'>CVE
-2015-7853</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7852'>CVE
-2015-7852</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7851'>CVE
-2015-7851</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7850'>CVE
-2015-7850</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7849'>CVE
-2015-7849</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7848'>CVE
-2015-7848</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7701'>CVE
-2015-7701</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7703'>CVE
-2015-7703</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7704'>CVE
-2015-7704</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7705'>CVE
-2015-7705</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7691'>CVE
-2015-7691</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7692'>CVE
-2015-7692</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7702'>CVE
-2015-7702</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1798'>CVE
-2015-1798</a>

<a
href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1799'>CVE
-2015-1799</a>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1798'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1799'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5194'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5300'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7691'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7692'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7701'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7702'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7703'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7704'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7705'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7848'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7849'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7850'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7851'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7852'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7853'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7854'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7855'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7871'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7973'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7974'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7975'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7976'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7977'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7978'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7979'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8138'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8158'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1547'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1548'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1549'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1550'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1551'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2516'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2517'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2518'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2519'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4953'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4954'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4955'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4956'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4957'"
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
    value:"https://bugzilla.suse.com/920893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924202"
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
    value:"https://bugzilla.suse.com/943218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944300"
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
    value:"https://bugzilla.suse.com/951629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957226"
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
    value:"https://bugzilla.suse.com/962995"
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
    value:"https://bugzilla.suse.com/977450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988565"
  );
  # https://download.suse.com/patch/finder/?keywords=e7685b9a0cc48dfc1cea383e011b438b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?802995db"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5194.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-8158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2516.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4953.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4954.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4957.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161912-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7baed9b6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", reference:"ntp-4.2.8p8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"ntp-doc-4.2.8p8-0.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
