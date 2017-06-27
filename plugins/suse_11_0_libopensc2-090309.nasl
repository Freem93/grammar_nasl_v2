#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libopensc2-598.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40031);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:38:14 $");

  script_cve_id("CVE-2009-0368");

  script_name(english:"openSUSE Security Update : libopensc2 (libopensc2-598)");
  script_summary(english:"Check for the libopensc2-598 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Private data objects on smartcards initialized with OpenSC could be
accessed without authentication (CVE-2009-0368).

Only blank cards initialized with OpenSC are affected by this problem.
Affected cards need to be manually fixed, updating the opensc package
alone is not sufficient!

Please carefully read and follow the instructions on the following
website if you are using PIN protected private data objects on smart
cards other than Oberthur, and you have initialized those cards using
OpenSC: http://en.opensuse.org/Smart_Cards/Advisories"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.opensuse.org/Smart_Cards/Advisories"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480262"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libopensc2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopensc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopensc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/09");
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

if ( rpm_check(release:"SUSE11.0", reference:"libopensc2-0.11.4-37.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"opensc-0.11.4-37.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"opensc-devel-0.11.4-37.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libopensc2-32bit-0.11.4-37.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"opensc-32bit-0.11.4-37.6") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopensc2 / libopensc2-32bit / opensc / opensc-32bit / etc");
}
