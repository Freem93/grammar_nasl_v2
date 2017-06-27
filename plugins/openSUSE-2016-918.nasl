#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-918.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92654);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/08/01 15:11:53 $");

  script_name(english:"openSUSE Security Update : dropbear (openSUSE-2016-918)");
  script_summary(english:"Check for the openSUSE-2016-918 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dropbear fixes four security issues (bnc#990363) :

  - A format string injection vulnerability allowed remotes
    attacker to run arbitrary code as root if specific
    usernames including '%' symbols could be created on the
    target system. If a dbclient user can control usernames
    or host arguments, or untrusted input is processed,
    potentially arbitrary code could have been executed as
    the dbclient user.

  - When importing malicious OpenSSH key files via
    dropbearconvert, arbitrary code could have been executed
    as the local dropbearconvert user

  - If particular -m or -c arguments were provided, as used
    in scripts, dbclient could have executed arbitrary code

  - dbclient or dropbear server could have exposed process
    memory to the running user if compiled with DEBUG_TRACE
    and running with -v

Dropbear was updated to the upstream 2016.74 release, including fixes
for the following upstream issues :

  - Port forwarding failure when connecting to domains that
    have both IPv4 and IPv6 addresses

  - 100% CPU use while waiting for rekey to complete

  - Fix crash when fallback initshells() is used scp failing
    when the local user doesn't exist

The following upstream improvements are included :

  - Support syslog in dbclient, option -o usesyslog=yes

  - Kill a proxycommand when dbclient exits

  - Option to exit when a TCP forward fails

  - Allow specifying commands eg 'dropbearmulti dbclient
    ...' instead of symlinks"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990363"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dropbear packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dropbear-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"dropbear-2016.74-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dropbear-debuginfo-2016.74-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dropbear-debugsource-2016.74-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dropbear / dropbear-debuginfo / dropbear-debugsource");
}
