#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-449.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76340);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/08 20:44:31 $");

  script_cve_id("CVE-2014-0178", "CVE-2014-0244", "CVE-2014-3493");

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2014:0857-1)");
  script_summary(english:"Check for the openSUSE-2014-449 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"samba was updated to fix three security issues and two non-security
issues. &#9; These security issues were fixed :

  - Fix segmentation fault in smbd_marshall_dir_entry()'s
    SMB_FIND_FILE_UNIX handler (CVE-2014-3493)

  - Fix nmbd denial of service (CVE-2014-0244)

  - Fix malformed FSCTL_SRV_ENUMERATE_SNAPSHOTS response
    (CVE-2014-0178)

These non-security issues were fixed :

  - Fix printer job purging; (bso#10612); (bnc#879390).

  - Package the get_printing_ticket binary with 0700
    permissions on post-11.4 systems; (bnc#685093)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-07/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=685093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=872396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=879390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883758"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/02");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libnetapi-devel-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient-devel-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes-devel-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient-devel-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debugsource-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-devel-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-debuginfo-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.12-59.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.12-59.23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
