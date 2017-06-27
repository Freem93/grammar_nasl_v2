#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-17.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74918);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/03 15:02:31 $");

  script_cve_id("CVE-2012-0759", "CVE-2012-5829", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0751", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771");

  script_name(english:"openSUSE Security Update : firefox / seamonkey / thunderbird (openSUSE-SU-2013:0149-1)");
  script_summary(english:"Check for the openSUSE-2013-17 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla January 8th 2013 security release contains updates :

Mozilla Firefox was updated to version 18.0. Mozilla SeaMonkey was
updated to version 2.15. Mozilla Thunderbird was updated to version
17.0.2. Mozilla XULRunner was updated to version 17.0.2.

  - MFSA 2013-01/CVE-2013-0749/CVE-2013-0769/CVE-2013-0770
    Miscellaneous memory safety hazards

  - MFSA
    2013-02/CVE-2013-0760/CVE-2013-0762/CVE-2013-0766/CVE-20
    13-0767
    CVE-2013-0761/CVE-2013-0763/CVE-2013-0771/CVE-2012-5829
    Use-after-free and buffer overflow issues found using
    Address Sanitizer

  - MFSA 2013-03/CVE-2013-0768 (bmo#815795) Buffer Overflow
    in Canvas

  - MFSA 2013-04/CVE-2012-0759 (bmo#802026) URL spoofing in
    addressbar during page loads

  - MFSA 2013-05/CVE-2013-0744 (bmo#814713) Use-after-free
    when displaying table with many columns and column
    groups

  - MFSA 2013-06/CVE-2013-0751 (bmo#790454) Touch events are
    shared across iframes

  - MFSA 2013-07/CVE-2013-0764 (bmo#804237) Crash due to
    handling of SSL on threads

  - MFSA 2013-08/CVE-2013-0745 (bmo#794158)
    AutoWrapperChanger fails to keep objects alive during
    garbage collection

  - MFSA 2013-09/CVE-2013-0746 (bmo#816842) Compartment
    mismatch with quickstubs returned values

  - MFSA 2013-10/CVE-2013-0747 (bmo#733305) Event
    manipulation in plugin handler to bypass same-origin
    policy

  - MFSA 2013-11/CVE-2013-0748 (bmo#806031) Address space
    layout leaked in XBL objects

  - MFSA 2013-12/CVE-2013-0750 (bmo#805121) Buffer overflow
    in JavaScript string concatenation

  - MFSA 2013-13/CVE-2013-0752 (bmo#805024) Memory
    corruption in XBL with XML bindings containing SVG

  - MFSA 2013-14/CVE-2013-0757 (bmo#813901) Chrome Object
    Wrapper (COW) bypass through changing prototype

  - MFSA 2013-15/CVE-2013-0758 (bmo#813906) Privilege
    escalation through plugin objects

  - MFSA 2013-16/CVE-2013-0753 (bmo#814001) Use-after-free
    in serializeToStream

  - MFSA 2013-17/CVE-2013-0754 (bmo#814026) Use-after-free
    in ListenerManager

  - MFSA 2013-18/CVE-2013-0755 (bmo#814027) Use-after-free
    in Vibrate

  - MFSA 2013-19/CVE-2013-0756 (bmo#814029) Use-after-free
    in JavaScript Proxy objects

Mozilla NSPR was updated to 4.9.4, containing some small bugfixes and
new features.

Mozilla NSS was updated to 3.14.1 containing various new features,
security fix and bugfixes :

  - MFSA 2013-20/CVE-2013-0743 (bmo#825022, bnc#796628)
    revoke mis-issued intermediate certificates from
    TURKTRUST

Cryptographic changes done :

  - Support for TLS 1.1 (RFC 4346)

  - Experimental support for DTLS 1.0 (RFC 4347) and
    DTLS-SRTP (RFC 5764)

  - Support for AES-CTR, AES-CTS, and AES-GCM

  - Support for Keying Material Exporters for TLS (RFC 5705)

  - Support for certificate signatures using the MD5 hash
    algorithm is now disabled by default

  - The NSS license has changed to MPL 2.0. Previous
    releases were released under a MPL 1.1/GPL 2.0/LGPL 2.1
    tri-license. For more information about MPL 2.0, please
    see http://www.mozilla.org/MPL/2.0/FAQ.html. For an
    additional explanation on GPL/LGPL compatibility, see
    security/nss/COPYING in the source code.

  - Export and DES cipher suites are disabled by default.
    Non-ECC AES and Triple DES cipher suites are enabled by
    default

Please see http://www.mozilla.org/security/announce/ for more
information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-01/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/MPL/2.0/FAQ.html."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796628"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox / seamonkey / thunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 17.0.1 Flash Privileged Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-18.0-2.58.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.5.0+17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.5.0+17.0.2-33.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-debuginfo-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-debuginfo-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-4.9.4-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debuginfo-4.9.4-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debugsource-4.9.4-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-devel-4.9.4-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-debuginfo-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debuginfo-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debugsource-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-devel-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-debuginfo-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-debuginfo-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.15-2.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.4-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.4-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.14.1-9.21.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.2-2.53.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-18.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-debuginfo-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.5.0+17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-debuginfo-1.5.0+17.0.2-49.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreebl3-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreebl3-debuginfo-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsoftokn3-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsoftokn3-debuginfo-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-debuginfo-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-4.9.4-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debuginfo-4.9.4-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debugsource-4.9.4-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-devel-4.9.4-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-certs-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-certs-debuginfo-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-debuginfo-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-debugsource-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-devel-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-sysinit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-sysinit-debuginfo-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-tools-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-tools-debuginfo-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debuginfo-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debugsource-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-dom-inspector-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-irc-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-common-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-other-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-venkman-2.15-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-buildsymbols-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debuginfo-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debugsource-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-debuginfo-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.4-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.4-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.14.1-2.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-32bit-17.0.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.2-2.26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
