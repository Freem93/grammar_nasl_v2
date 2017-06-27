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
  script_id(69343);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/16 19:47:29 $");

  script_cve_id("CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1706", "CVE-2013-1707", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1712", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : Mozilla Firefox (SAT Patch Numbers 8187 / 8191)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Firefox 17.0.8esr (bnc#833389) addresses :

  - (bmo#855331, bmo#844088, bmo#858060, bmo#870200,
    bmo#874974, bmo#861530, bmo#854157, bmo#893684,
    bmo#878703, bmo#862185, bmo#879139, bmo#888107,
    bmo#880734). (MFSA 2013-63 / CVE-2013-1701 /
    CVE-2013-1702)

Miscellaneous memory safety hazards have been fixed (rv:23.0 /
rv:17.0.8) :

  - (bmo#888314, bmo#888361) Buffer overflow in Mozilla
    Maintenance Service and Mozilla Updater. (MFSA 2013-66 /
    CVE-2013-1706 / CVE-2013-1707)

  - (bmo#848253) Document URI misrepresentation and
    masquerading. (MFSA 2013-68 / CVE-2013-1709)

  - (bmo#871368) CRMF requests allow for code execution and
    XSS attacks. (MFSA 2013-69 / CVE-2013-1710)

  - (bmo#859072) Further Privilege escalation through
    Mozilla Updater. (MFSA 2013-71 / CVE-2013-1712)

  - (bmo#887098) Wrong principal used for validating URI for
    some JavaScript components. (MFSA 2013-72 /
    CVE-2013-1713)

  - (bmo#879787) Same-origin bypass with web workers and
    XMLHttpRequest. (MFSA 2013-73 / CVE-2013-1714)

  - (bmo#406541) Local Java applets may read contents of
    local file system. (MFSA 2013-75 / CVE-2013-1717)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-63.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-69.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-71.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-72.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-73.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-75.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1701.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1706.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1707.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1710.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1712.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1713.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1714.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1717.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8187 / 8191 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox toString console.time Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-17.0.8esr-0.7.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-17.0.8esr-0.7.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-17.0.8esr-0.7.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.8esr-0.7.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"MozillaFirefox-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.8esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"MozillaFirefox-17.0.8esr-0.7.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-17.0.8esr-0.7.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-17.0.8esr-0.7.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.8esr-0.7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
