#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ldapsmb-3115.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75568);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2010-3069");

  script_name(english:"openSUSE Security Update : ldapsmb (openSUSE-SU-2010:0653-1)");
  script_summary(english:"Check for the ldapsmb-3115 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow in the sid_parse() function of samba could
potentially be exploited by remote attackers to execute arbitrary code
(CVE-2010-3069).

Additionally the update also contains fixes for the following
non-security issues :

bnc#567013 - Failed to join ADS Domain bnc#573246 - mounted shares via
mount.cifs disappear when dhclient renews lease bnc#592198 - Samba 3.0
/ 3.2 doesn't work with Windows 2008 R2 (NTLMv2) bnc#599873 - SAMBA -
Problem using NTLM authentication with 2008R2 bnc#613459 - winbindd
crashes in rpccli_set_timeout bnc#617153 - new printers are not seen
in samba with registry bnc#619787 - Samba Causes Too Many Files In Use
Error On Windows 7 bnc#630812 - net ads join failing due to malformed
UPN bnc#632055 - No authentication dialog to access SMB share through
Nautilus bnc#632852 - root preexec does not work as expected"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-09/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=613459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=630812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ldapsmb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/15");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"ldapsmb-1.34b-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libldb-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libldb0-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libnetapi-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libnetapi0-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbclient-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbclient0-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbsharemodes-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbsharemodes0-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtalloc-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtalloc2-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtdb-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtdb1-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtevent-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtevent0-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libwbclient-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libwbclient0-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-client-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-devel-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-krb-printing-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-winbind-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libsmbclient0-32bit-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libtdb1-32bit-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libwbclient0-32bit-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"samba-32bit-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"samba-client-32bit-3.5.4-5.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"samba-winbind-32bit-3.5.4-5.1.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldapsmb / libldb-devel / libldb0 / libnetapi-devel / libnetapi0 / etc");
}
