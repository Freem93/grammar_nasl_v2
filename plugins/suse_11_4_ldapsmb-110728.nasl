#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ldapsmb-4939.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75890);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-2522", "CVE-2011-2694");

  script_name(english:"openSUSE Security Update : ldapsmb (openSUSE-SU-2011:0998-1)");
  script_summary(english:"Check for the ldapsmb-4939 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A Cross-Site Request Forgery (CSRF) and a Cross Site Scripting
vulnerability have been fixed in samba's SWAT. CVE-2011-2522 and
CVE-2011-2694 have been assigned."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-09/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=705170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=705241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708503"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ldapsmb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb0-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"ldapsmb-1.34b-300.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libldb-devel-0.9.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libldb0-0.9.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libldb0-debuginfo-0.9.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libnetapi-devel-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libnetapi0-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libnetapi0-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbclient-devel-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbclient0-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbclient0-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbsharemodes-devel-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbsharemodes0-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbsharemodes0-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtalloc-devel-2.0.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtalloc2-2.0.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtalloc2-debuginfo-2.0.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtdb-devel-1.2.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtdb1-1.2.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtdb1-debuginfo-1.2.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtevent-devel-0.9.8-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtevent0-0.9.8-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtevent0-debuginfo-0.9.8-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libwbclient-devel-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libwbclient0-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libwbclient0-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-client-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-client-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-debugsource-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-devel-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-krb-printing-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-krb-printing-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-winbind-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-winbind-debuginfo-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsmbclient0-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtalloc2-32bit-2.0.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.0.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtdb1-32bit-1.2.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.2.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libwbclient0-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-client-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-winbind-32bit-3.5.7-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.5.7-3.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
