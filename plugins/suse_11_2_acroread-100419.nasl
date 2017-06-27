#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update acroread-2321.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45600);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 19:55:06 $");

  script_cve_id("CVE-2010-0190", "CVE-2010-0191", "CVE-2010-0192", "CVE-2010-0193", "CVE-2010-0194", "CVE-2010-0195", "CVE-2010-0196", "CVE-2010-0197", "CVE-2010-0198", "CVE-2010-0199", "CVE-2010-0201", "CVE-2010-0202", "CVE-2010-0203", "CVE-2010-0204", "CVE-2010-1241");

  script_name(english:"openSUSE Security Update : acroread (openSUSE-SU-2010:0137-1)");
  script_summary(english:"Check for the acroread-2321 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted PDF documents could crash acroread or even lead to
execution of arbitrary code (CVE-2010-0190, CVE-2010-0191,
CVE-2010-0192, CVE-2010-0193 CVE-2010-0194, CVE-2010-0195,
CVE-2010-0196, CVE-2010-0197 CVE-2010-0198, CVE-2010-0199,
CVE-2010-0201, CVE-2010-0202 CVE-2010-0203, CVE-2010-0204,
CVE-2010-1241)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-04/msg00075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=595108"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acroread packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/22");
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
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"acroread-9.3.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-cmaps-9.3.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-ja-9.3.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-ko-9.3.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-zh_CN-9.3.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-zh_TW-9.3.2-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread / acroread-cmaps / acroread-fonts-ja / acroread-fonts-ko / etc");
}
