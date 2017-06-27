#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-296.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74953);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/31 14:21:57 $");

  script_cve_id("CVE-2012-1667", "CVE-2012-3817", "CVE-2012-3868", "CVE-2012-4244", "CVE-2012-5166", "CVE-2012-5688", "CVE-2013-2266");
  script_osvdb_id(82609, 84228, 84229, 85417, 86118, 88126, 91712);

  script_name(english:"openSUSE Security Update : bind (openSUSE-SU-2013:0605-1)");
  script_summary(english:"Check for the openSUSE-2013-296 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"bind was updated to 9.8.4-P2 to fix security problems and bugs.

Security Fixes Removed the check for regex.h in configure in order to
disable regex syntax checking, as it exposes BIND to a critical flaw
in libregex on some platforms. [CVE-2013-2266] [RT #32688]
https://kb.isc.org/article/AA-00871 (bnc#811876) Prevents named from
aborting with a require assertion failure on servers with DNS64
enabled. These crashes might occur as a result of specific queries
that are received. (Note that this fix is a subset of a series of
updates that will be included in full in BIND 9.8.5 and 9.9.3 as
change #3388, RT #30996). [CVE-2012-5688] [RT #30792] A deliberately
constructed combination of records could cause named to hang while
populating the additional section of a response. [CVE-2012-5166] [RT
#31090] Prevents a named assert (crash) when queried for a record
whose RDATA exceeds 65535 bytes [CVE-2012-4244] [RT #30416] Prevents a
named assert (crash) when validating caused by using 'Bad cache' data
before it has been initialized. [CVE-2012-3817] [RT #30025] A
condition has been corrected where improper handling of zero-length
RDATA could cause undesirable behavior, including termination of the
named process. [CVE-2012-1667] [RT #29644] New Features Elliptic Curve
Digital Signature Algorithm keys and signatures in DNSSEC are now
supported per RFC 6605. [RT #21918] Feature Changes Improves OpenSSL
error logging [RT #29932] nslookup now returns a nonzero exit code
when it is unable to get an answer. [RT #29492] Bug Fixes Uses binary
mode to open raw files on Windows. [RT #30944] Static-stub zones now
accept 'forward' and 'fowarders' options (often needed for subdomains
of the zone referenced to override global forwarding options). These
options are already available with traditional stub zones and their
omission from zones of type 'static-stub' was an inadvertent
oversight. [RT #30482] Limits the TTL of signed RRsets in cache when
their RRSIGs are approaching expiry. This prevents the persistence in
cache of invalid RRSIGs in order to assist recovery from a situation
where zone re-signing doesn't occur in a timely manner. With this
change, named will attempt to obtain new RRSIGs from the authoritative
server once the original ones have expired, and even if the TTL of the
old records would in other circumstances cause them to be kept in
cache for longer. [RT #26429] Corrects the syntax of isc_atomic_xadd()
and isc_atomic_cmpxchg() which are employed on Itanium systems to
speed up lock management by making use of atomic operations. Without
the syntax correction it is possible that concurrent access to the
same structures could accidentally occur with unpredictable results.
[RT #25181] The configure script now supports and detects
libxml2-2.8.x correctly [RT #30440] The host command should no longer
assert on some architectures and builds while handling the time values
used with the -w (wait forever) option. [RT #18723] Invalid zero
settings for max-retry-time, min-retry-time, max-refresh-time,
min-refresh-time will now be detected during parsing of named.conf and
an error emitted instead of triggering an assertion failure on
startup. [RT #27730] Removes spurious newlines from log messages in
zone.c [RT #30675] When built with readline support (i.e. on a system
with readline installed) nsupdate no longer terminates unexpectedly in
interactive mode. [RT #29550] All named tasks that perform
task-exclusive operations now share the same single task. Prior to
this change, there was the possibility of a race condition between
rndc operations and other functions such as re-sizing the adb hash
table. If the race condition was encountered, named would in most
cases terminate unexpectedly with an assert. [RT #29872] Ensures that
servers are expired from the ADB cache when the timeout limit is
reached so that their learned attributes can be refreshed. Prior to
this change, servers that were frequently queried might never have
their entries removed and reinitialized. This is of particular
importance to DNSSEC-validating recursive servers that might
erroneously set 'no-edns' for an authoritative server following a
period of intermittent connectivity. [RT #29856] Adds additional
resilience to a previous security change (3218) by preventing RRSIG
data from being added to cache when a pseudo-record matching the
covering type and proving non-existence exists at a higher trust
level. The earlier change prevented this inconsistent data from being
retrieved from cache in response to client queries - with this
additional change, the RRSIG records are no longer inserted into cache
at all. [RT #26809] dnssec-settime will now issue a warning when the
writing of a new private key file would cause a change in the
permissions of the existing file. [RT #27724] Fixes the defect
introduced by change #3314 that was causing failures when saving stub
zones to disk (resulting in excessive CPU usage in some cases). [RT
#29952] It is now possible to using multiple control keys again - this
functionality was inadvertently broken by change #3924 (RT #28265)
which addressed a memory leak. [RT #29694] Setting
resolver-query-timeout too low could cause named problems recovering
after a loss of connectivity. [RT #29623] Reduces the potential
build-up of stale RRsets in cache on a busy recursive nameserver by
re-using cached DS and RRSIG rrsets when possible [RT #29446] Corrects
a failure to authenticate non-existence of resource records in some
circumstances when RPZ has been configured. Also :

  - adds an optional 'recursive-only yes|no' to the
    response-policy statement

  - adds an optional 'max-policy-ttl' to the response-policy
    statement to limit the false data that 'recursive-only
    no' can introduce into resolvers' caches

  - introduces a predefined encoding of PASSTHRU policy by
    adding 'rpz-passthru' to be used as the target of CNAME
    policy records (the old encoding is still accepted.)

  - adds a RPZ performance test to bin/tests/system/rpz when
    queryperf is available. [RT #26172]
    Upper-case/lower-case handling of RRSIG signer-names is
    now handled consistently: RRSIG records are generated
    with the signer-name in lower case. They are accepted
    with any case, but if they fail to validate, we try
    again in lower case. [RT #27451]

  - Update the IPv4 address of the D root name server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-00871"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/27");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"bind-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-chrootenv-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-debuginfo-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-debugsource-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-devel-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-libs-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-libs-debuginfo-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-lwresd-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-lwresd-debuginfo-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-utils-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bind-utils-debuginfo-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"bind-libs-32bit-9.8.4P2-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.8.4P2-4.32.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
