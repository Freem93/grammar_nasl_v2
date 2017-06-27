#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-819.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75186);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1705", "CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597", "CVE-2013-5598", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604");
  script_bugtraq_id(61871, 62460, 62463, 62467, 62469, 62473, 62475, 62478, 62479, 63415, 63416, 63417, 63418, 63419, 63420, 63421, 63422, 63423, 63424, 63427, 63428, 63429, 63430);
  script_osvdb_id(96014, 97388, 97389, 97390, 97391, 97392, 97398, 97401, 97404, 99082, 99083, 99084, 99085, 99086, 99087, 99088, 99089, 99090, 99091, 99092, 99093, 99094, 99095);

  script_name(english:"openSUSE Security Update : Mozilla Suite (openSUSE-SU-2013:1633-1)");
  script_summary(english:"Check for the openSUSE-2013-819 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to Firefox 25.0. MozillaThunderbird was
updated to Thunderbird 24.1.0. Mozilla XULRunner was updated to
17.0.10esr. Mozilla NSPR was updated to 4.10.1.

Changes in MozillaFirefox :

  - requires NSS 3.15.2 or above

  - MFSA 2013-93/CVE-2013-5590/CVE-2013-5591/CVE-2013-5592
    Miscellaneous memory safety hazards

  - MFSA 2013-94/CVE-2013-5593 (bmo#868327) Spoofing
    addressbar through SELECT element

  - MFSA 2013-95/CVE-2013-5604 (bmo#914017) Access violation
    with XSLT and uninitialized data

  - MFSA 2013-96/CVE-2013-5595 (bmo#916580) Improperly
    initialized memory and overflows in some JavaScript
    functions

  - MFSA 2013-97/CVE-2013-5596 (bmo#910881) Writing to cycle
    collected object during image decoding

  - MFSA 2013-98/CVE-2013-5597 (bmo#918864) Use-after-free
    when updating offline cache

  - MFSA 2013-99/CVE-2013-5598 (bmo#920515) Security bypass
    of PDF.js checks using iframes

  - MFSA 2013-100/CVE-2013-5599/CVE-2013-5600/CVE-2013-5601
    (bmo#915210, bmo#915576, bmo#916685) Miscellaneous
    use-after-free issues found through ASAN fuzzing

  - MFSA 2013-101/CVE-2013-5602 (bmo#897678) Memory
    corruption in workers

  - MFSA 2013-102/CVE-2013-5603 (bmo#916404) Use-after-free
    in HTML document templates

Changes in MozillaThunderbird :

  - requires NSS 3.15.2 or above

  - MFSA 2013-93/CVE-2013-5590/CVE-2013-5591/CVE-2013-5592
    Miscellaneous memory safety hazards

  - MFSA 2013-94/CVE-2013-5593 (bmo#868327) Spoofing
    addressbar through SELECT element

  - MFSA 2013-95/CVE-2013-5604 (bmo#914017) Access violation
    with XSLT and uninitialized data

  - MFSA 2013-96/CVE-2013-5595 (bmo#916580) Improperly
    initialized memory and overflows in some JavaScript
    functions

  - MFSA 2013-97/CVE-2013-5596 (bmo#910881) Writing to cycle
    collected object during image decoding

  - MFSA 2013-98/CVE-2013-5597 (bmo#918864) Use-after-free
    when updating offline cache

  - MFSA 2013-100/CVE-2013-5599/CVE-2013-5600/CVE-2013-5601
    (bmo#915210, bmo#915576, bmo#916685) Miscellaneous
    use-after-free issues found through ASAN fuzzing

  - MFSA 2013-101/CVE-2013-5602 (bmo#897678) Memory
    corruption in workers

  - MFSA 2013-102/CVE-2013-5603 (bmo#916404) Use-after-free
    in HTML document templates

  - update to Thunderbird 24.0.1

  - fqdn for smtp server name was not accepted (bmo#913785)

  - fixed crash in PL_strncasecmp (bmo#917955)

  - update Enigmail to 1.6

  - The passphrase timeout configuration in Enigmail is now
    read and written from/to gpg-agent.

  - New dialog to change the expiry date of keys

  - New function to search for the OpenPGP keys of all
    Address Book entries on a keyserver

  - removed obsolete enigmail-build.patch

Changes in xulrunner :

  - update to 17.0.10esr (bnc#847708)

  - require NSS 3.14.4 or above

  - MFSA 2013-93/CVE-2013-5590/CVE-2013-5591/CVE-2013-5592
    Miscellaneous memory safety hazards

  - MFSA 2013-95/CVE-2013-5604 (bmo#914017) Access violation
    with XSLT and uninitialized data

  - MFSA 2013-96/CVE-2013-5595 (bmo#916580) Improperly
    initialized memory and overflows in some JavaScript
    functions

  - MFSA 2013-98/CVE-2013-5597 (bmo#918864) Use-after-free
    when updating offline cache

  - MFSA 2013-100/CVE-2013-5599/CVE-2013-5600/CVE-2013-5601
    (bmo#915210, bmo#915576, bmo#916685) Miscellaneous
    use-after-free issues found through ASAN fuzzing

  - MFSA 2013-101/CVE-2013-5602 (bmo#897678) Memory
    corruption in workers

  - update to 17.0.9esr (bnc#840485)

  - MFSA 2013-65/CVE-2013-1705 (bmo#882865) Buffer underflow
    when generating CRMF requests

  - MFSA 2013-76/CVE-2013-1718 Miscellaneous memory safety
    hazards

  - MFSA 2013-79/CVE-2013-1722 (bmo#893308) Use-after-free
    in Animation Manager during stylesheet cloning

  - MFSA 2013-82/CVE-2013-1725 (bmo#876762) Calling scope
    for new JavaScript objects can lead to memory corruption

  - MFSA 2013-88/CVE-2013-1730 (bmo#851353) Compartment
    mismatch re-attaching XBL-backed nodes

  - MFSA 2013-89/CVE-2013-1732 (bmo#883514) Buffer overflow
    with multi-column, lists, and floats

  - MFSA 2013-90/CVE-2013-1735/CVE-2013-1736 (bmo#898871,
    bmo#906301) Memory corruption involving scrolling

  - MFSA 2013-91/CVE-2013-1737 (bmo#907727) User-defined
    properties on DOM proxies get the wrong 'this' object

Changes in mozilla-nspr :

  - update to version 4.10.1

  - bmo#888273: RWIN Scaling (RFC1323) limited to 2 on
    Windows 7 and 8 (Windows only)

  - bmo#907512: Unix platforms shouldn't mask errors
    specific to Unix domain sockets"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847708"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Suite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/04");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-25.0-2.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.6.0+24.1.0-49.59.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-debuginfo-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-4.10.1-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debuginfo-4.10.1-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debugsource-4.10.1-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-devel-4.10.1-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-buildsymbols-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debuginfo-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debugsource-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-debuginfo-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.1-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.1-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-32bit-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.10-2.56.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-25.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-1.6.0+24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-debuginfo-1.6.0+24.1.0-61.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-debuginfo-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-4.10.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debuginfo-4.10.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debugsource-4.10.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-devel-4.10.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-buildsymbols-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debuginfo-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debugsource-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-debuginfo-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-32bit-17.0.10-1.30.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.10-1.30.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Suite");
}
