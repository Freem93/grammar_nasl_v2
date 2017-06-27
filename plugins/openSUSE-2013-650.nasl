#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-650.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75120);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852");
  script_osvdb_id(95970, 96080, 96081, 96210);

  script_name(english:"openSUSE Security Update : filezilla (openSUSE-SU-2013:1347-1)");
  script_summary(english:"Check for the openSUSE-2013-650 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"FileZilla was updated to version 3.7.3 to add various features, fix
bugs and also security issues in the embedded putty ssh client.

Full changelog: https://filezilla-project.org/changelog.php

  - Noteworthy changes :

  - Apply a fix for a security vulnerability in PuTTY as
    used in FileZilla to handle SFTP. See CVE-2013-4852 for
    reference.

  - Merge further fixes from PuTTY to address CVE-2013-4206,
    CVE-2013-4207, CVE-2013-4208

  - Version bump to 3.7.0.1

  - Fix issues with bundled gnutls

  - Update translations

  - Update to version 3.7.0. Changes since 3.6.0.2 :

  - Show total transfer speed as tooltip over the transfer
    indicators

  - List supported protocols in tooltip of host field in
    quickconnect bar

  - Use TLS instead of the deprecated term SSL

  - Reworded text when saving of passwords is disabled, do
    not refer to kiosk mode

  - Improved usability of Update page in settings dialog

  - Improve SFTP performance

  - When navigating to the parent directory, highlight the
    former child

  - When editing files, use high priority for the transfers

  - Add label to size conditions in filter conditions dialog
    indicating that the unit is bytes

  - Ignore drag&drop operations where source and target are
    identical and clarify the wording in some drop error
    cases

  - Trim whitespace from the entered port numbers

  - Slightly darker color of inactive tabs

  - Ignore .. item in the file list context menus if
    multiple items are selected

  - Display TLS version and key exchange algorithm in
    certificate and encryption details dialog for FTP over
    TLS connections.

  - Fix handling of remote paths containing double-quotes

  - Fix crash when opening local directories in Explorer if
    the name contained characters not representable in the
    locale's narrow-width character set.

  - Fix a memory leak in the host key verification dialog
    for SFTP

  - Fix drag-scrolling in file lists with very low height

  - Don't attempt writing XML files upon loading them

  - Improve handling of legacy DDE file associations

  - Fix handling of HTTPS in the auto updater in case a
    mirror redirects to HTTPS

  - Update to version 3.6.0.2. Changes since 3.5.3 :

  - 3.6.0.2 (2012-11-29)

  - Fix problems with stalling FTP over TLS uploads

  - MSW: Minor performance increase listing local files

  - 3.6.0.1 (2012-11-18)

  - Fix problems with TLS cipher selection, including a
    bugfix for GnuTLS

  - Fix a crash on shutdown

  - Add log message for servers not using UTF-8

  - Small performance and memory optimizations getting file
    types

  - Improve formatting of transfer speeds

  - 3.6.0 (2012-11-10)

  - Fix a crash introduced since 3.5.3

  - IPv6-only hosts should no longer cause a crash in the
    network configuration wizard"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://filezilla-project.org/changelog.php"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected filezilla packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:filezilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:filezilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:filezilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:filezilla-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"filezilla-3.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"filezilla-debuginfo-3.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"filezilla-debugsource-3.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"filezilla-lang-3.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"filezilla-3.7.3-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"filezilla-debuginfo-3.7.3-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"filezilla-debugsource-3.7.3-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"filezilla-lang-3.7.3-5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "filezilla");
}
