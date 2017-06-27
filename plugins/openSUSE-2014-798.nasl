#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-798.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80211);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/23 13:49:35 $");

  script_cve_id("CVE-2014-8601");

  script_name(english:"openSUSE Security Update : pdns-recursor (openSUSE-SU-2014:1685-1)");
  script_summary(english:"Check for the openSUSE-2014-798 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This pdns-recursor version update fixes the following security issue
and non secuirty issues.

Update to upstream release 3.6.2.

  - boo#906583: Degraded service through queries to queries
    to specific domains (CVE-2014-8601)

  - Fixed broken _localstatedir

Update to upstream release 3.6.1.

  - gab14b4f: expedite servfail generation for ezdns-like
    failures (fully abort query resolving if we hit more
    than 50 outqueries)

  - g42025be: PowerDNS now polls the security status of a
    release at startup and periodically. More detail on this
    feature, and how to turn it off, can be found in Section
    2, 'Security polling'.

  - g5027429: We did not transmit the right 'local' socket
    address to Lua for TCP/IP queries in the recursor. In
    addition, we would attempt to lookup a filedescriptor
    that wasn't there in an unlocked map which could
    conceivably lead to crashes. Closes t1828, thanks
    Winfried for reporting

  - g752756c: Sync embedded yahttp copy. API: Replace HTTP
    Basic auth with static key in custom header

  - g6fdd40d: add missing #include <pthread.h> to
    rec-channel.hh (this fixes building on OS X).

  - sync permissions/ownership of home and config dir with
    the pdns package

  - added systemd support for 12.3 and newer

Update to upstrean release 3.5.3.

  - This is a bugfix and performance update to 3.5.2. It
    brings serious performance improvements for dual stack
    users. For all the details see
    http://doc.powerdns.com/html/changelog.html#changelog-re
    cursor-3.5.3

  - Remove patch (pdns-recursor-3.3_config.patch)

  - Add patch (pdns-recursor-3.5.3_config.patch)

Update to upstrean release 3.5.2.

  - Responses without the QR bit set now get matched up to
    an outstanding query, so that resolution can be aborted
    early instead of waiting for a timeout.

  - The depth limiter changes in 3.5.1 broke some legal
    domains with lots of indirection.

  - Slightly improved logging to aid debugging.

Update to upstream version 3.5.1.

  - This is a stability and bugfix update to 3.5. It
    contains important fixes that improve operation for
    certain domains. This is a stability, security and
    bugfix update to 3.3/3.3.1. It contains important fixes
    for slightly broken domain names, which your users
    expect to work anyhow. For all details see
    http://doc.powerdns.com/html/changelog.html#changelog-re
    cursor-3.5.1

  - adapted patches: pdns-rec-lua52.patch
    pdns-recursor-3.5.1_config.patch

  - fixed conditional for different lua versions

  - started some basic support to build packages for non
    suse distros"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://doc.powerdns.com/html/changelog.html#changelog-recursor-3.5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://doc.powerdns.com/html/changelog.html#changelog-recursor-3.5.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906583"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pdns-recursor packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");
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

if ( rpm_check(release:"SUSE12.3", reference:"pdns-recursor-3.6.2-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pdns-recursor-debuginfo-3.6.2-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pdns-recursor-debugsource-3.6.2-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pdns-recursor-3.6.2-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pdns-recursor-debuginfo-3.6.2-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pdns-recursor-debugsource-3.6.2-8.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns-recursor / pdns-recursor-debuginfo / pdns-recursor-debugsource");
}
