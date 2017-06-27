#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-110.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74546);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-4362");

  script_name(english:"openSUSE Security Update : lighttpd (openSUSE-2012-110)");
  script_summary(english:"Check for the openSUSE-2012-110 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - added lighttpd-1.4.30_head_fixes.patch: cherry picked 4
    fixes from HEAD :

  - [ssl] include more headers explicitly

  - list all network handlers in lighttpd -V (fixes
    lighttpd#2376)

  - Move fdevent subsystem includes to implementation files
    to reduce conflicts (fixes lighttpd#2373)

  - [ssl] fix segfault in counting renegotiations for
    openssl versions without TLSEXT/SNI

  - update to 1.4.30: (bnc#733607)

  - Always use our &lsquo;own&rsquo; md5 implementation,
    fixes linking issues on MacOS (fixes #2331)

  - Limit amount of bytes we send in one go; fixes stalling
    in one connection and timeouts on slow systems.

  - [ssl] fix build errors when Elliptic-Curve
    Diffie-Hellman is disabled

  - Add static-file.disable-pathinfo option to prevent
    handling of urls like &hellip;/secret.php/image.jpg as
    static file

  - Don&rsquo;t overwrite 401 (auth required) with 501
    (unknown method) (fixes #2341)

  - Fix mod_status bug: always showed &ldquo;0/0&rdquo; in
    the &ldquo;Read&rdquo; column for uploads (fixes #2351)

  - [mod_auth] Fix signedness error in http_auth (fixes
    #2370, CVE-2011-4362)

  - [ssl] count renegotiations to prevent client
    renegotiations

  - [ssl] add option to honor server cipher order (fixes
    #2364, BEAST attack)

  - [core] accept dots in ipv6 addresses in host header
    (fixes #2359)

  - [ssl] fix ssl connection aborts if files are larger than
    the MAX_WRITE_LIMIT (256kb)

  - [libev/cgi] fix waitpid ECHILD errors in cgi with libev
    (fixes #2324)

  - add automake as buildrequire to avoid implicit
    dependency"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-debuginfo-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-debugsource-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_cml-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_cml-debuginfo-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_geoip-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_geoip-debuginfo-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_magnet-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_magnet-debuginfo-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_mysql_vhost-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_rrdtool-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_trigger_b4_dl-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_webdav-1.4.30-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lighttpd-mod_webdav-debuginfo-1.4.30-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-debugsource / etc");
}
