#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-778.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75173);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/24 13:49:14 $");

  script_cve_id("CVE-2013-4359");
  script_bugtraq_id(62328);
  script_osvdb_id(97184);

  script_name(english:"openSUSE Security Update : proftpd (openSUSE-SU-2013:1563-1)");
  script_summary(english:"Check for the openSUSE-2013-778 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"proftpd was updated to 1.3.4d.

  - Fixed broken build when using --disable-ipv6 configure
    option

  - Fixed mod_sql 'SQLAuthType Backend' MySQL issues

  - fix for bnc#843444 (CVE-2013-4359)

  - http://bugs.proftpd.org/show_bug.cgi?id=3973

  - add proftpd-sftp-kbdint-max-responses-bug3973.patch

  - Improve systemd service file 

  - use upstream tmpfiles.d file. related to [bnc#811793]

  - Use /run instead of /var/run 

  - update to 1.3.4c

  - Added Spanish translation.

  - Fixed several mod_sftp issues, including
    SFTPPassPhraseProvider, handling of symlinks for
    REALPATH requests, and response code logging.

  - Fixed symlink race for creating directories when
    UserOwner is in effect.

  - Increased performance of FTP directory listings.

  - rebase and rename patches (remove version string)

  - proftpd-1.3.4a-dist.patch -> proftpd-dist.patch

  - proftpd-1.3.4a-ftpasswd.patch -> proftpd-ftpasswd.patch

  - proftpd-1.3.4a-strip.patch -> proftpd-strip.patch

  - fix proftpd.conf (rebase basic.conf patch)

  - IdentLookups is now a separate module <IfModule
    mod_ident.c> IdentLookups on/off </IfModule> is needed
    and module is not built cause crrodriguez disabled it.

  - fix for bnc#787884
    (https://bugzilla.novell.com/show_bug.cgi?id=787884)

  - added extra Source proftpd.conf.tmpfile

  - Disable ident lookups, this protocol is totally obsolete
    and dangerous. (add --disable-ident)

  - Fix debug info generation ( add --disable-strip) 

  - Add systemd unit 

  - update to 1.3.4b

  + Fixed mod_ldap segfault on login when LDAPUsers with no
    filters used.

  + Fixed sporadic SFTP upload issues for large files.

  + Fixed SSH2 handling for some clients (e.g. OpenVMS).

  + New FactsOptions directive; see
    doc/modules/mod_facts.html#FactsOptions

  + Fixed build errors on Tru64, AIX, Cygwin.

  - add Source Signatuire (.asc) file

  - add noBuildDate patch

  - add lang pkg

  - --enable-nls

  - add configure option

  - --enable-openssl, --with-lastlog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.proftpd.org/show_bug.cgi?id=3973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843444"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/14");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"proftpd-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-debuginfo-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-debugsource-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-devel-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-lang-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-ldap-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-ldap-debuginfo-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-mysql-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-mysql-debuginfo-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-pgsql-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-pgsql-debuginfo-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-radius-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-radius-debuginfo-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-sqlite-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"proftpd-sqlite-debuginfo-1.3.4d-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-debuginfo-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-debugsource-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-devel-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-lang-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-ldap-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-ldap-debuginfo-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-mysql-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-mysql-debuginfo-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-pgsql-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-pgsql-debuginfo-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-radius-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-radius-debuginfo-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-sqlite-1.3.4d-4.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"proftpd-sqlite-debuginfo-1.3.4d-4.4.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd");
}
