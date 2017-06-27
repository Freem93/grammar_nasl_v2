#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update cifs-mount-406.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39927);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:09:49 $");

  script_cve_id("CVE-2008-4314", "CVE-2009-0022");

  script_name(english:"openSUSE Security Update : cifs-mount (cifs-mount-406)");
  script_summary(english:"Check for the cifs-mount-406 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a bug that allowed the client to retrieve arbitrary
memory content from the server process. (CVE-2008-4314) Additionally
another bug was fixed that affects environments that enabled registry
shares by setting 'registry shares = yes'. In this case an
authenticated user is accidentally allowed to access the root
filesystem '/'. (CVE-2009-0022)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=446971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=460764"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cifs-mount packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_cwe_id(20, 200);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.0", reference:"cifs-mount-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ldapsmb-1.34b-195.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libnetapi-devel-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libnetapi0-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbclient-devel-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbclient0-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbsharemodes-devel-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libsmbsharemodes0-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtalloc-devel-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtalloc1-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtdb-devel-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtdb1-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libwbclient-devel-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libwbclient0-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-client-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-devel-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-krb-printing-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"samba-winbind-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libsmbclient0-32bit-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libtalloc1-32bit-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libtdb1-32bit-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libwbclient0-32bit-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"samba-32bit-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"samba-client-32bit-3.2.4-4.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"samba-winbind-32bit-3.2.4-4.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
