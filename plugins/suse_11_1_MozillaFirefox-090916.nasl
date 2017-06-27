#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-1312.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(41039);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:21:18 $");

  script_cve_id("CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-1312)");
  script_summary(english:"Check for the MozillaFirefox-1312 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to the 3.0.14 stable release.

It also fixes various security issues: MFSA 2009-47 / CVE-2009-3069 /
CVE-2009-3070 / CVE-2009-3071 / CVE-2009-3072 / CVE-2009-3073 /
CVE-2009-3074 / CVE-2009-3075: Mozilla developers and community
members identified and fixed several stability bugs in the browser
engine used in Firefox and other Mozilla-based products. Some of these
crashes showed evidence of memory corruption under certain
circumstances and we presume that with enough effort at least some of
these could be exploited to run arbitrary code.

MFSA 2009-48 / CVE-2009-3076: Mozilla security researcher Jesse
Rudermanreported that when security modules were added or removed via
pkcs11.addmodule or pkcs11.deletemodule, the resulting dialog was not
sufficiently informative. Without sufficient warning, an attacker
could entice a victim to install a malicious PKCS11 module and affect
the cryptographic integrity of the victim's browser. Security
researcher Dan Kaminsky reported that this issue had not been fixed in
Firefox 3.0 and that under certain circumstances pkcs11 modules could
be installed from a remote location. Firefox 3.5 releases are not
affected.

MFSA 2009-49 / CVE-2009-3077: An anonymous security researcher, via
TippingPoint's Zero Day Initiative, reported that the columns of a XUL
tree element could be manipulated in a particular way which would
leave a pointer owned by the column pointing to freed memory. An
attacker could potentially use this vulnerability to crash a victim's
browser and run arbitrary code on the victim's computer.

MFSA 2009-50 / CVE-2009-3078: Security researcher Juan Pablo Lopez
Yacubian reported that the default Windows font used to render the
locationbar and other text fields was improperly displaying certain
Unicode characters with tall line-height. In such cases the tall
line-height would cause the rest of the text in the input field to be
scrolled vertically out of view. An attacker could use this
vulnerability to prevent a user from seeing the URL of a malicious
site. Corrie Sloot also independently reported this issue to Mozilla.

MFSA 2009-51 / CVE-2009-3079: Mozilla security researcher moz_bug_r_a4
reported that the BrowserFeedWriter could be leveraged to run
JavaScript code from web content with elevated privileges. Using this
vulnerability, an attacker could construct an object containing
malicious JavaScript and cause the FeedWriter to process the object,
running the malicious code with chrome privileges. Thunderbird does
not support the BrowserFeedWriter object and is not vulnerable in its
default configuration. Thunderbird might be vulnerable if the user has
installed any add-on which adds a similarly implemented feature and
then enables JavaScript in mail messages. This is not the default
setting and we strongly discourage users from running JavaScript in
mail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=534458"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom190");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/22");
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

if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-3.0.14-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-branding-upstream-3.0.14-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaFirefox-translations-3.0.14-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-1.9.0.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-devel-1.9.0.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-xulrunner190-translations-1.9.0.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-xpcom190-1.9.0.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.14-0.1.1") ) flag++;

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
