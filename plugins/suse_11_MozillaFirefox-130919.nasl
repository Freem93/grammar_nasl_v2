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
  script_id(70189);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2013-1705", "CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1726", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : Mozilla Firefox (SAT Patch Numbers 8344 / 8346)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Firefox 17.0.9esr (bnc#840485) addresses :

  - User-defined properties on DOM proxies get the wrong
    'this' object. (MFSA 2013-91)

    -. (CVE-2013-1737)

  - Memory corruption involving scrolling. (MFSA 2013-90)

  - use-after-free in mozilla::layout::ScrollbarActivity.
    (CVE-2013-1735)

  - Memory corruption in nsGfxScrollFrameInner::IsLTR().
    (CVE-2013-1736)

  - Buffer overflow with multi-column, lists, and floats.
    (MFSA 2013-89)

  - buffer overflow at nsFloatManager::GetFlowArea() with
    multicol, list, floats. (CVE-2013-1732)

  - compartment mismatch re-attaching XBL-backed nodes.
    (MFSA 2013-88)

  - compartment mismatch in nsXBLBinding::DoInitJSClass.
    (CVE-2013-1730)

  - Mozilla Updater does not lock MAR file after signature
    verification. (MFSA 2013-83)

  - MAR signature bypass in Updater could lead to downgrade.
    (CVE-2013-1726)

  - Calling scope for new JavaScript objects can lead to
    memory corruption. (MFSA 2013-82)

  - ABORT: bad scope for new JSObjects: ReparentWrapper /
    document.open. (CVE-2013-1725)

  - Use-after-free in Animation Manager during stylesheet
    cloning. (MFSA 2013-79)

  - Heap-use-after-free in
    nsAnimationManager::BuildAnimations. (CVE-2013-1722)

  - Miscellaneous memory safety hazards (rv:24.0 /
    rv:17.0.9). (MFSA 2013-76)

  - Memory safety bugs fixed in Firefox 17.0.9 and Firefox
    24.0. (CVE-2013-1718)

  - Buffer underflow when generating CRMF requests. (MFSA
    2013-65)

  - ASAN heap-buffer-overflow (read 1) in
    cryptojs_interpret_key_gen_type (CVE-2013-1705)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-65.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-76.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-79.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-82.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-83.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-88.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-89.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-90.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-91.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1725.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1726.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1732.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1735.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1737.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8344 / 8346 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-17.0.9esr-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-17.0.9esr-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-17.0.9esr-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.9esr-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-17.0.9esr-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-17.0.9esr-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-17.0.9esr-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.9esr-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-17.0.9esr-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-translations-17.0.9esr-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-17.0.9esr-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-17.0.9esr-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
