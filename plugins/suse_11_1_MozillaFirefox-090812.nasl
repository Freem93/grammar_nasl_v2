#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-1202.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40648);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:18 $");

  script_cve_id("CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-1202)");
  script_summary(english:"Check for the MozillaFirefox-1202 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to the 3.0.13 release, fixing some security
issues and bugs :

MFSA 2009-44 / CVE-2009-2654: Security researcher Juan Pablo Lopez
Yacubian reported that an attacker could call window.open() on an
invalid URL which looks similar to a legitimate URL and then use
document.write() to place content within the new document, appearing
to have come from the spoofed location. Additionally, if the spoofed
document was created by a document with a valid SSL certificate, the
SSL indicators would be carried over into the spoofed document. An
attacker could use these issues to display misleading location and SSL
information for a malicious web page.

MFSA 2009-45 / CVE-2009-2662:The browser engine in Mozilla Firefox
before 3.0.13, and 3.5.x before 3.5.2, allows remote attackers to
cause a denial of service (memory corruption and application crash) or
possibly execute arbitrary code via vectors related to the
TraceRecorder::snapshot function in js/src/jstracer.cpp, and
unspecified other vectors.

CVE-2009-2663 / MFSA 2009-45: libvorbis before r16182, as used in
Mozilla Firefox before 3.0.13 and 3.5.x before 3.5.2 and other
products, allows context-dependent attackers to cause a denial of
service (memory corruption and application crash) or possibly execute
arbitrary code via a crafted .ogg file.

CVE-2009-2664 / MFSA 2009-45: The js_watch_set function in
js/src/jsdbgapi.cpp in the JavaScript engine in Mozilla Firefox before
3.0.13, and 3.5.x before 3.5.2, allows remote attackers to cause a
denial of service (assertion failure and application exit) or possibly
execute arbitrary code via a crafted .js file, related to a 'memory
safety bug.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527489"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gconf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gconf2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:orbit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:orbit2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom190");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-3.0.13-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-branding-upstream-3.0.13-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-translations-3.0.13-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"gconf2-2.24.0-2.15") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libidl-0.8.11-1.27") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-devel-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-translations-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"orbit2-2.14.16-1.23") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-xpcom190-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"gconf2-2.24.0-2.17") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"gconf2-32bit-2.24.0-2.15") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libidl-0.8.11-1.33") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libidl-32bit-0.8.11-1.27") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.13-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"orbit2-2.14.16-1.28") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"orbit2-32bit-2.14.16-1.23") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
