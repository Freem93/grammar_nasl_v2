#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1435.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95707);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/12 14:40:36 $");

  script_cve_id("CVE-2016-8734");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-2016-1435)");
  script_summary(english:"Check for the openSUSE-2016-1435 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for subversion fixes the following issues :

  - Version update to 1.9.5 :

  - Unrestricted XML entity expansion in mod_dontdothat and
    Subversion clients using http(s):// (boo#1011552,
    CVE-2016-8734)

  - Client-side bugfixes :

  - fix accessing non-existent paths during reintegrate
    merge (r1766699 et al)

  - fix handling of newly secured subdirectories in working
    copy (r1724448)

  - info: remove trailing whitespace in --show-item=revision
    (issue #4660)

  - fix recording wrong revisions for tree conflicts
    (r1734106)

  - gpg-agent: improve discovery of gpg-agent sockets
    (r1766327)

  - gpg-agent: fix file descriptor leak (r1766323)

  - resolve: fix --accept=mine-full for binary files (issue
    #4647)

  - merge: fix possible crash (issue #4652)

  - resolve: fix possible crash (r1748514)

  - fix potential crash in Win32 crash reporter (r1663253 et
    al)

  - Server-side bugfixes :

  - fsfs: fix 'offset too large' error during pack (issue
    #4657)

  - svnserve: enable hook script environments (r1769152)

  - fsfs: fix possible data reconstruction error (issue
    #4658)

  - fix source of spurious 'incoming edit' tree conflicts
    (r1770108)

  - fsfs: improve caching for large directories (r1721285)

  - fsfs: fix crash when encountering all-zero checksums
    (r1759686)

  - fsfs: fix potential source of repository corruptions
    (r1756266)

  - mod_dav_svn: fix excessive memory usage with
    mod_headers/mod_deflate (issue #3084)

  - mod_dav_svn: reduce memory usage during GET requests
    (r1757529 et al)

  - fsfs: fix unexpected 'database is locked' errors
    (r1741096 et al)

  - fsfs: fix opening old repositories without db/format
    files (r1720015)

  - Client-side and server-side bugfixes :

  - fix possible crash when reading invalid configuration
    files (r1715777)

  - Bindings bugfixes :

  - swig-pl: do not corrupt '{DATE}' revision variable
    (r1767768)

  - javahl: fix temporary accepting SSL server certificates
    (r1764851)

  - swig-pl: fix possible stack corruption (r1683266,
    r1683267)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011552"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-ctypes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libsvn_auth_gnome_keyring-1-0-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsvn_auth_kwallet-1-0-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-bash-completion-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-debuginfo-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-debugsource-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-devel-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-perl-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-perl-debuginfo-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-python-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-python-ctypes-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-python-debuginfo-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-ruby-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-ruby-debuginfo-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-server-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-server-debuginfo-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-tools-1.9.5-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"subversion-tools-debuginfo-1.9.5-3.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsvn_auth_gnome_keyring-1-0 / etc");
}
