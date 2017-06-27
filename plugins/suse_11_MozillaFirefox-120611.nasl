#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64208);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2011-3101", "CVE-2012-0441", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1939", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1942", "CVE-2012-1943", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947");

  script_name(english:"SuSE 11.1 Security Update : Mozilla Firefox (SAT Patch Number 6425)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to 10.0.5ESR fixing various bugs and
security issues.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-34)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.
    References

    Jesse Ruderman, Igor Bukanov, Bill McCloskey, Christian
    Holler, Andrew McCreight, and Brian Bondy reported
    memory safety problems and crashes that affect Firefox
    12. (CVE-2012-1938)

    Christian Holler reported a memory safety problem that
    affects Firefox ESR. (CVE-2012-1939)

    Igor Bukanov, Olli Pettay, Boris Zbarsky, and Jesse
    Ruderman reported memory safety problems and crashes
    that affect Firefox ESR and Firefox 13. (CVE-2012-1937)

    Ken Russell of Google reported a bug in NVIDIA graphics
    drivers that they needed to work around in the Chromium
    WebGL implementation. Mozilla has done the same in
    Firefox 13 and ESR 10.0.5. (CVE-2011-3101)

  - Security researcher James Forshaw of Context Information
    Security found two issues with the Mozilla updater and
    the Mozilla updater service introduced in Firefox 12 for
    Windows. The first issue allows Mozilla's updater to
    load a local DLL file in a privileged context. The
    updater can be called by the Updater Service or
    independently on systems that do not use the service.
    The second of these issues allows for the updater
    service to load an arbitrary local DLL file, which can
    then be run with the same system privileges used by the
    service. Both of these issues require local file system
    access to be exploitable. (MFSA 2012-35)

    Possible Arbitrary Code Execution by Update Service
    (CVE-2012-1942) Updater.exe loads wsock32.dll from
    application directory. (CVE-2012-1943)

  - Security researcher Adam Barth found that inline event
    handlers, such as onclick, were no longer blocked by
    Content Security Policy's (CSP) inline-script blocking
    feature. Web applications relying on this feature of CSP
    to protect against cross-site scripting (XSS) were not
    fully protected. (CVE-2012-1944). (MFSA 2012-36)

  - Security researcher Paul Stone reported an attack where
    an HTML page hosted on a Windows share and then loaded
    could then load Windows shortcut files (.lnk) in the
    same share. These shortcut files could then link to
    arbitrary locations on the local file system of the
    individual loading the HTML page. That page could show
    the contents of these linked files or directories from
    the local file system in an iframe, causing information
    disclosure. (MFSA 2012-37)

    This issue could potentially affect Linux machines with
    samba shares enabled. (CVE-2012-1945)

  - Security researcher Arthur Gerkis used the Address
    Sanitizer tool to find a use-after-free while
    replacing/inserting a node in a document. This
    use-after-free could possibly allow for remote code
    execution. (CVE-2012-1946). (MFSA 2012-38)

  - Security researcher Kaspar Brand found a flaw in how the
    Network Security Services (NSS) ASN.1 decoder handles
    zero length items. Effects of this issue depend on the
    field. One known symptom is an unexploitable crash in
    handling OCSP responses. NSS also mishandles zero-length
    basic constraints, assuming default values for some
    types that should be rejected as malformed. These issues
    have been addressed in NSS 3.13.4, which is now being
    used by Mozilla. (CVE-2012-0441). (MFSA 2012-39)

  - Security researcher Abhishek Arya of Google used the
    Address Sanitizer tool to uncover several issues: two
    heap buffer overflow bugs and a use-after-free problem.
    The first heap buffer overflow was found in conversion
    from unicode to native character sets when the function
    fails. The use-after-free occurs in nsFrameList when
    working with column layout with absolute positioning in
    a container that changes size. The second buffer
    overflow occurs in nsHTMLReflowState when a window is
    resized on a page with nested columns and a combination
    of absolute and relative positioning. All three of these
    issues are potentially exploitable. (MFSA 2012-40)

    Heap-buffer-overflow in utf16_to_isolatin1
    (CVE-2012-1947) Heap-use-after-free in
    nsFrameList::FirstChild. (CVE-2012-1940)

    Heap-buffer-overflow in
    nsHTMLReflowState::CalculateHypotheticalBox, with nested
    multi-column, relative position, and absolute position.
    (CVE-2012-1941)

More information on security issues can be found on:
http://www.mozilla.org/security/announce/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-40.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1937.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1938.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1939.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1940.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1941.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1942.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1943.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1944.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1945.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1946.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1947.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6425.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-10.0.5-0.3.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-translations-10.0.5-0.3.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libfreebl3-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nspr-4.9.1-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nss-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nss-tools-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-10.0.5-0.3.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.5-0.3.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libfreebl3-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libfreebl3-32bit-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-4.9.1-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.1-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-tools-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-10.0.5-0.3.6")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-translations-10.0.5-0.3.6")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libfreebl3-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nspr-4.9.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nss-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nss-tools-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libfreebl3-32bit-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-nss-32bit-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libfreebl3-32bit-3.13.5-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.5-0.4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
