#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update samba-2553.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27427);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:36:49 $");

  script_cve_id("CVE-2007-0452");

  script_name(english:"openSUSE 10 Security Update : samba (samba-2553)");
  script_summary(english:"Check for the samba-2553 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A logic error in the deferred open code can lead to an infinite loop
in Samba's smbd daemon (CVE-2007-0452).

In addition the following changes are included with these packages :

  - Move tdb utils to the client package.

  - Add version of the package subversion to Samba vendor
    version suffix.

  - Fix time value reporting in libsmbclient; [#195285].

  - Store and restore NT hashes as string compatible values;
    [#185053].

  - Added winbindd null sid fix; [#185053].

  - Fix from Alison Winters of SGI to build even if
    make_vscan is 0.

  - Send correct workstation name to prevent
    NT_STATUS_INVALID_WORKSTATION beeing returned in
    samlogon; [#148645], [#161051]."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"samba-3.0.22-13.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-client-3.0.22-13.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-winbind-3.0.22-13.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-32bit-3.0.22-13.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-client-32bit-3.0.22-13.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.22-13.27") ) flag++;

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
