#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-131.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88552);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-7208", "CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1933", "CVE-2016-1935", "CVE-2016-1937", "CVE-2016-1938", "CVE-2016-1939", "CVE-2016-1942", "CVE-2016-1943", "CVE-2016-1944", "CVE-2016-1945", "CVE-2016-1946", "CVE-2016-1947");

  script_name(english:"openSUSE Security Update : Mozilla Firefox (openSUSE-2016-131)");
  script_summary(english:"Check for the openSUSE-2016-131 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security related issues by updating
packages to a more recent version :

Update of NSPR to 4.11 Update of NSS to 3.21 Update of Firefox to 44.0

  - MFSA 2016-01/CVE-2016-1930/CVE-2016-1931 Miscellaneous
    memory safety hazards

  - MFSA 2016-02/CVE-2016-1933 (bmo#1231761) Out of Memory
    crash when parsing GIF format images

  - MFSA 2016-03/CVE-2016-1935 (bmo#1220450) Buffer overflow
    in WebGL after out of memory allocation

  - MFSA 2016-04/CVE-2015-7208/CVE-2016-1939 (bmo#1191423,
    bmo#1233784) Firefox allows for control characters to be
    set in cookie names

  - MFSA 2016-06/CVE-2016-1937 (bmo#724353) Missing delay
    following user click events in protocol handler dialog

  - MFSA 2016-07/CVE-2016-1938 (bmo#1190248) Errors in
    mp_div and mp_exptmod cryptographic functions in NSS
    (fixed by requiring NSS 3.21)

  - MFSA 2016-09/CVE-2016-1942/CVE-2016-1943 (bmo#1189082,
    bmo#1228590) Addressbar spoofing attacks

  - MFSA 2016-10/CVE-2016-1944/CVE-2016-1945/CVE-2016-1946
    (bmo#1186621, bmo#1214782, bmo#1232096) Unsafe memory
    manipulation found through code inspection

  - MFSA 2016-11/CVE-2016-1947 (bmo#1237103) Application
    Reputation service disabled in Firefox 43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-44.0-103.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-4.11-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debuginfo-4.11-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debugsource-4.11-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-devel-4.11-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.11-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.11-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.21-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.21-68.1") ) flag++;

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
