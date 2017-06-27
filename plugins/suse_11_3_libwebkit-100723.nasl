#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libwebkit-2806.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75627);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/14 15:20:34 $");

  script_cve_id("CVE-2010-1386", "CVE-2010-1392", "CVE-2010-1405", "CVE-2010-1407", "CVE-2010-1416", "CVE-2010-1417", "CVE-2010-1418", "CVE-2010-1421", "CVE-2010-1422", "CVE-2010-1664", "CVE-2010-1665", "CVE-2010-1758", "CVE-2010-1759", "CVE-2010-1760", "CVE-2010-1761", "CVE-2010-1762", "CVE-2010-1767", "CVE-2010-1770", "CVE-2010-1771", "CVE-2010-1772", "CVE-2010-1773", "CVE-2010-1774");

  script_name(english:"openSUSE Security Update : libwebkit (openSUSE-SU-2010:0458-1)");
  script_summary(english:"Check for the libwebkit-2806 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The libwebkit browser engine version 1.2.3 fixes several security
relevant bugs

(CVE-2010-1386, CVE-2010-1392, CVE-2010-1405, CVE-2010-1407,
CVE-2010-1416, CVE-2010-1417, CVE-2010-1665, CVE-2010-1418,
CVE-2010-1421, CVE-2010-1422, CVE-2010-1501, CVE-2010-1767,
CVE-2010-1664, CVE-2010-1758, CVE-2010-1759, CVE-2010-1760,
CVE-2010-1761, CVE-2010-1762, CVE-2010-1770, CVE-2010-1771,
CVE-2010-1772, CVE-2010-1773, CVE-2010-1774)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name="
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-08/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=622994"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwebkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-1_0-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-1_0-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.3", reference:"libwebkit-1_0-2-1.2.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libwebkit-devel-1.2.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libwebkit-lang-1.2.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"webkit-jsc-1.2.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libwebkit-1_0-2-32bit-1.2.3-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwebkit-1_0-2 / libwebkit-1_0-2-32bit / libwebkit-devel / etc");
}
