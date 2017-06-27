#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update amarok-436.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39909);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:09:49 $");

  script_cve_id("CVE-2009-0135", "CVE-2009-0136");

  script_name(english:"openSUSE Security Update : amarok (amarok-436)");
  script_summary(english:"Check for the amarok-436 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of amarok fixes several integer overflows and unchecked
memory allocations that can be exploited by malformed Audible digital
audio files. These bugs could be used in a user-assisted attack
scenario to execute arbitrary code remotely. (CVE-2009-0135,
CVE-2009-0136)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465098"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected amarok packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amarok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amarok-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amarok-libvisual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amarok-xine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amarok-yauap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/19");
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

if ( rpm_check(release:"SUSE11.0", reference:"amarok-1.4.9.1-27.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"amarok-lang-1.4.9.1-27.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"amarok-libvisual-1.4.9.1-27.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"amarok-xine-1.4.9.1-27.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"amarok-yauap-1.4.9.1-27.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "amarok");
}
