#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gmime-2_4-1983.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44905);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:00:35 $");

  script_cve_id("CVE-2010-0409");

  script_name(english:"openSUSE Security Update : gmime-2_4 (gmime-2_4-1983)");
  script_summary(english:"Check for the gmime-2_4-1983 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of gmime fixes a buffer overflow in the GMIME_UUENCODE_LEN
macro which allowed possible code execution while processing uuencoded
data. (CVE-2010-0409: CVSS v2 Base Score: 5.8)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576923"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gmime-2_4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gmime-2_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gmime-2_4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gmime-2_4-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmime-2_4-2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"gmime-2_4-2.4.8-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"gmime-2_4-devel-2.4.8-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"gmime-2_4-sharp-2.4.8-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libgmime-2_4-2-2.4.8-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gmime-2_4");
}
