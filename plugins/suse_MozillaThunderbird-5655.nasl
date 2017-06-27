#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-5655.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34345);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070");

  script_name(english:"openSUSE 10 Security Update : MozillaThunderbird (MozillaThunderbird-5655)");
  script_summary(english:"Check for the MozillaThunderbird-5655 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Thunderbird to version 2.0.0.17.

It contains the following security fixes: MFSA 2008-46 /
CVE-2008-4070: Heap overflow when canceling a newsgroup message

MFSA 2008-44 / CVE-2008-4067 / CVE-2008-4068: resource: traversal
vulnerabilities

MFSA 2008-43: BOM characters stripped from JavaScript before execution
CVE-2008-4065: Stripped BOM characters bug CVE-2008-4066: HTML escaped
low surrogates bug

MFSA 2008-42 Crashes with evidence of memory corruption
(rv:1.9.0.2/1.8.1.17): CVE-2008-4061: Jesse Ruderman reported a crash
in the layout engine. CVE-2008-4062: Igor Bukanov, Philip Taylor,
Georgi Guninski, and Antoine Labour reported crashes in the JavaScript
engine. CVE-2008-4063: Jesse Ruderman, Bob Clary, and Martijn Wargers
reported crashes in the layout engine which only affected Firefox 3.
CVE-2008-4064: David Maciejak and Drew Yao reported crashes in
graphics rendering which only affected Firefox 3.

MFSA 2008-41 Privilege escalation via XPCnativeWrapper pollution
CVE-2008-4058: XPCnativeWrapper pollution bugs CVE-2008-4059:
XPCnativeWrapper pollution (Firefox 2) CVE-2008-4060: Documents
without script handling objects

MFSA 2008-38 / CVE-2008-3835: nsXMLDocument::OnChannelRedirect()
same-origin violation

MFSA 2008-37 / CVE-2008-0016: UTF-8 URL stack buffer overflow

For more details:
http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.ht
ml"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?280be806"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"MozillaThunderbird-2.0.0.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaThunderbird-translations-2.0.0.17-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
