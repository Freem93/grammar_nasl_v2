#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libopensc2-5587.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34261);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_cve_id("CVE-2008-2235");

  script_name(english:"openSUSE 10 Security Update : libopensc2 (libopensc2-5587)");
  script_summary(english:"Check for the libopensc2-5587 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a security issues with opensc that occured when
initializing blank smart cards with Siemens CardOS M4. After the
initialization anyone could set the PIN of the smart card without
authorization (CVE-2008-2235).

NOTE: Already initialized cards are still vulnerable after this
update. Please use the command-line tool pkcs15-tool with option

--test-update and --update when necessary.

Please find more information at
http://www.opensc-project.org/security.html

This is the second attempt to fix this problem. The previous update
was unforunately incomplete."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opensc-project.org/security.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libopensc2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopensc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopensc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"opensc-0.11.1-22") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"opensc-devel-0.11.1-22") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libopensc2-0.11.3-21.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"opensc-0.11.3-21.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"opensc-devel-0.11.3-21.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libopensc2-32bit-0.11.3-21.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"opensc-32bit-0.11.3-21.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc / opensc-devel / libopensc2 / libopensc2-32bit / etc");
}
