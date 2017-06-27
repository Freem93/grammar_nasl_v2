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
  script_id(53647);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/11/29 15:23:52 $");

  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0076", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");

  script_name(english:"SuSE 11.1 Security Update : Mozilla Firefox (SAT Patch Number 4463)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 3.6.17 security release.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. Credits. (MFSA 2011-12)

    Mozilla developer Scoobidiver reported a memory safety
    issue which affected Firefox 4 and Firefox 3.6.
    (CVE-2011-0081)

  - The web development team of Alcidion reported a crash
    that affected Firefox 4, Firefox 3.6 and Firefox 3.5.
    (CVE-2011-0069) Ian Beer reported a crash that affected
    Firefox 4, Firefox 3.6 and Firefox 3.5. (CVE-2011-0070)

    Mozilla developers Bob Clary, Henri Sivonen, Marco
    Bonardo, Mats Palmgren and Jesse Ruderman reported
    memory safety issues which affected Firefox 3.6 and
    Firefox 3.5. (CVE-2011-0080)

    Aki Helin reported memory safety issues which affected
    Firefox 3.6 and Firefox 3.5. (CVE-2011-0074 /
    CVE-2011-0075)

    Ian Beer reported memory safety issues which affected
    Firefox 3.6 and Firefox 3.5. (CVE-2011-0077 /
    CVE-2011-0078)

    Martin Barbella reported a memory safety issue which
    affected Firefox 3.6 and Firefox 3.5. (CVE-2011-0072)

  - Security researcher regenrecht reported several dangling
    pointer vulnerabilities via TippingPoint's Zero Day
    Initiative. (MFSA 2011-13 / CVE-2011-0065 /
    CVE-2011-0066 / CVE-2011-0073)

  - Security researcher Paul Stone reported that a Java
    applet could be used to mimic interaction with form
    autocomplete controls and steal entries from the form
    history. (MFSA 2011-14 / CVE-2011-0067)

  - David Remahl of Apple Product Security reported that the
    Java Embedding Plugin (JEP) shipped with the Mac OS X
    versions of Firefox could be exploited to obtain
    elevated access to resources on a user's system. (MFSA
    2011-15 / CVE-2011-0076)

  - Security researcher Soroush Dalili reported that the
    resource: protocol could be exploited to allow directory
    traversal on Windows and the potential loading of
    resources from non-permitted locations. The impact would
    depend on whether interesting files existed in
    predictable locations in a useful format. For example,
    the existence or non-existence of particular images
    might indicate whether certain software was installed.
    (MFSA 2011-16 / CVE-2011-0071)

  - Chris Evans of the Chrome Security Team reported that
    the XSLT generate-id() function returned a string that
    revealed a specific valid address of an object on the
    memory heap. It is possible that in some cases this
    address would be valuable information that could be used
    by an attacker while exploiting a different memory
    corruption but, in order to make an exploit more
    reliable or work around mitigation features in the
    browser or operating system. (MFSA 2011-18 /
    CVE-2011-1202)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1202.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4463.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-3.6.17-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-translations-3.6.17-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-gnome-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-translations-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-3.6.17-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-translations-3.6.17-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-3.6.17-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-translations-3.6.17-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-gnome-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-translations-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-xulrunner192-32bit-1.9.2.17-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.17-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
