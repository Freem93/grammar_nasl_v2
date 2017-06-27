#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64134);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:41:53 $");

  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");

  script_name(english:"SuSE 11.2 Security Update : Mozilla Firefox (SAT Patch Number 7004)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 10.0.10ESR security release.

The following issue has been fixed :

  - Mozilla has fixed a number of issues related to the
    Location object in order to enhance overall security.
    Details for each of the current fixed issues are below.
    (MFSA 2012-90)

    Thunderbird is only affected by window.location issues
    through RSS feeds and extensions that load web content.

  - Security researcher Mariusz Mlynski reported that the
    true value of window.location could be shadowed by user
    content through the use of the valueOf method, which can
    be combined with some plugins to perform a cross-site
    scripting (XSS) attack on users. (CVE-2012-4194)

  - Mozilla security researcher moz_bug_r_a4 discovered that
    the CheckURL function in window.location can be forced
    to return the wrong calling document and principal,
    allowing a cross-site scripting (XSS) attack. There is
    also the possibility of gaining arbitrary code execution
    if the attacker can take advantage of an add-on that
    interacts with the page content. (CVE-2012-4195)

  - Security researcher Antoine Delignat-Lavaud of the
    PROSECCO research team at INRIA Paris reported the
    ability to use property injection by prototype to bypass
    security wrapper protections on the Location object,
    allowing the cross-origin reading of the Location
    object. (CVE-2012-4196)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-90.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4196.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7004.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/29");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-10.0.10-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-10.0.10-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nspr-4.9.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-10.0.10-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.10-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-4.9.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-10.0.10-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-translations-10.0.10-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nspr-4.9.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.3-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
