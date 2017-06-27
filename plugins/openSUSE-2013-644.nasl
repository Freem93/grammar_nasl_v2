#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-644.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75116);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:25:35 $");

  script_cve_id("CVE-2013-4124");
  script_osvdb_id(95969);

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2013:1339-1)");
  script_summary(english:"Check for the openSUSE-2013-644 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of samba fixed the following issues :

  - The pam_winbind require_membership_of option allows for
    a list of SID, but currently only provides buffer space
    for ~20; (bnc#806501).

  - Samba 3.0.x to 4.0.7 are affected by a denial of service
    attack on authenticated or guest connections;
    CVE-2013-4124; (bnc#829969).

  - PIDL: fix parsing linemarkers in preprocessor output;
    (bso#9636).

  - build:autoconf: fix output of syslog-facility check;
    (bso#9983).

  - libreplace: add a missing 'eval' to the
    AC_VERIFY_C_PROTOTYPE macro.

  - Remove ldapsmb from the main spec file.

  - Don't bzip2 the main tar ball, use the upstream gziped
    one instead.

  - Fix crash bug during Win8 sync; (bso#9822).

  - Check for system libtevent and link dbwrap_tool and
    dbwrap_torture against it; (bso#9881).

  - errno gets overwritten in call to check_parent_exists();
    (bso#9927).

  - Fix a bug of drvupgrade of smbcontrol; (bso#9941).

  - Document idmap_ad rfc2307 attribute requirements;
    (bso#9880); (bnc#820531).

  - Don't install the tdb utilities man pages on post-12.1
    systems; (bnc#823549).

  - Fix libreplace license ambiguity; (bso#8997);
    (bnc#765270).

  - Fix is_printer_published GUID retrieval; (bso#9900);
    (bnc#798856).

  - Fix 'map untrusted to domain' with NTLMv2; (bso#9817);
    (bnc#817919).

  - Don't modify the pidfile name when a custom config file
    path is used; (bnc#812929).

  - Add extra attributes for AD printer publishing;
    (bso#9378); (bnc#798856).

  - Fix vfs_catia module; (bso#9701); (bnc#824833).

  - Fix AD printer publishing; (bso#9378); (bnc#798856)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829969"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libnetapi-devel-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient-devel-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes-devel-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient-devel-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debugsource-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-devel-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-debuginfo-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.7-48.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.7-48.24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnetapi-devel / libnetapi0 / libnetapi0-debuginfo / etc");
}
