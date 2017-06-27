#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-375.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83801);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/26 13:52:13 $");

  script_cve_id("CVE-2011-3079", "CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710", "CVE-2015-2711", "CVE-2015-2712", "CVE-2015-2713", "CVE-2015-2715", "CVE-2015-2716", "CVE-2015-2717", "CVE-2015-2718");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2015-375)");
  script_summary(english:"Check for the openSUSE-2015-375 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox web browser was updated to version 38.0.1 to fix
several security and non-security issues. This update also includes a
Mozilla Network Security Services (NSS) update to version 3.18.1.

The following vulnerabilities and issues were fixed :

Changes in Mozilla Firefox :

  - update to Firefox 38.0.1 stability and regression fixes

  - Systems with first generation NVidia Optimus graphics
    cards may crash on start-up

  - Users who import cookies from Google Chrome can end up
    with broken websites

  - Large animated images may fail to play and may stop
    other images from loading

  - update to Firefox 38.0 (bnc#930622)

  - New tab-based preferences

  - Ruby annotation support

  - more info:
    https://www.mozilla.org/en-US/firefox/38.0/releasenotes/
    security fixes :

  - MFSA 2015-46/CVE-2015-2708/CVE-2015-2709 Miscellaneous
    memory safety hazards

  - MFSA 2015-47/VE-2015-0797 (bmo#1080995) Buffer overflow
    parsing H.264 video with Linux Gstreamer

  - MFSA 2015-48/CVE-2015-2710 (bmo#1149542) Buffer overflow
    with SVG content and CSS

  - MFSA 2015-49/CVE-2015-2711 (bmo#1113431) Referrer policy
    ignored when links opened by middle-click and context
    menu

  - MFSA 2015-50/CVE-2015-2712 (bmo#1152280) Out-of-bounds
    read and write in asm.js validation

  - MFSA 2015-51/CVE-2015-2713 (bmo#1153478) Use-after-free
    during text processing with vertical text enabled

  - MFSA 2015-53/CVE-2015-2715 (bmo#988698) Use-after-free
    due to Media Decoder Thread creation during shutdown

  - MFSA 2015-54/CVE-2015-2716 (bmo#1140537) Buffer overflow
    when parsing compressed XML

  - MFSA 2015-55/CVE-2015-2717 (bmo#1154683) Buffer overflow
    and out-of-bounds read while parsing MP4 video metadata

  - MFSA 2015-56/CVE-2015-2718 (bmo#1146724) Untrusted site
    hosting trusted page can intercept webchannel responses

  - MFSA 2015-57/CVE-2011-3079 (bmo#1087565) Privilege
    escalation through IPC channel messages

Changes in Mozilla NSS :

  - update to 3.18.1

  - Firefox target release 38

  - No new functionality is introduced in this release.
    Notable Changes :

  - The following CA certificate had the Websites and Code
    Signing trust bits restored to their original state to
    allow more time to develop a better transition strategy
    for affected sites :

  - OU = Equifax Secure Certificate Authority

  - The following CA certificate was removed :

  - CN = e-Guven Kok Elektronik Sertifika Hizmet Saglayicisi

  - The following intermediate CA certificate has been added
    as actively distrusted because it was mis-used to issue
    certificates for domain names the holder did not own or
    control :

  - CN=MCSHOLDING TEST, O=MCSHOLDING, C=EG

  - The version number of the updated root CA list has been
    set to 2.4

  - update to 3.18

  - Firefox target release 38 New functionality :

  - When importing certificates and keys from a PKCS#12
    source, it's now possible to override the nicknames,
    prior to importing them into the NSS database, using new
    API SEC_PKCS12DecoderRenameCertNicknames.

  - The tstclnt test utility program has new command-line
    options

    -C, -D, -b and -R. Use -C one, two or three times to
    print information about the certificates received from a
    server, and information about the locally found and
    trusted issuer certificates, to diagnose server side
    configuration issues. It is possible to run tstclnt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/firefox/38.0/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-38.0.1-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.18.1-55.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-38.0.1-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-debuginfo-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-debuginfo-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-debuginfo-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debuginfo-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debugsource-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-devel-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-debuginfo-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-debuginfo-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.18.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.18.1-12.1") ) flag++;

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
