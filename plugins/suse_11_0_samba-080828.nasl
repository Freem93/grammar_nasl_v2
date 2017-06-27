#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update samba-174.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40126);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:44:04 $");

  script_cve_id("CVE-2008-3789");

  script_name(english:"openSUSE Security Update : samba (samba-174)");
  script_summary(english:"Check for the samba-174 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update to version 3.2.3 of Samba.

This release includes several bugfixes and performance enhancements
for Samba and its components. It is recommended for every user to
update to this version.

Among several other bugs the following list shows some detail :

  - Fix a race condition in winbind leading to a crash
    (bnc#406623).

  - Fix emptying the printing queue; (bnc#411493).

  - Fix the webinface SWAT; (bnc#391969).

  - Fixed a file permission problem. (CVE-2008-3789)
    bnc#420634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=391969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=406623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=411493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=412589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=420634"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"cifs-mount-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ldapsmb-1.34b-195.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libnetapi-devel-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libnetapi0-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbclient-devel-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbclient0-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbsharemodes-devel-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbsharemodes0-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtalloc-devel-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtalloc1-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtdb-devel-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtdb1-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libwbclient-devel-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libwbclient0-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-client-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-devel-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-krb-printing-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-winbind-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libsmbclient0-32bit-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libtalloc1-32bit-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libtdb1-32bit-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libwbclient0-32bit-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"samba-32bit-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"samba-client-32bit-3.2.3-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"samba-winbind-32bit-3.2.3-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cifs-mount / ldapsmb / libnetapi-devel / libnetapi0 / etc");
}
