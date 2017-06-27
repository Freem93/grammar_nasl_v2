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
  script_id(74006);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/14 00:01:15 $");

  script_cve_id("CVE-2014-1492", "CVE-2014-1518", "CVE-2014-1520", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");

  script_name(english:"SuSE 11.3 Security Update : Mozilla Firefox (SAT Patch Number 9185)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Mozilla Firefox and Mozilla NSS update to 24.5.0esr fixes the
following several security and non-security issues :

  - Miscellaneous memory safety hazards. (MFSA 2014-34 /
    CVE-2014-1518)

  - Out of bounds read while decoding JPG images. (MFSA
    2014-37 / CVE-2014-1523)

  - Buffer overflow when using non-XBL object as XBL. (MFSA
    2014-38 / CVE-2014-1524)

  - Privilege escalation through Web Notification API. (MFSA
    2014-42 / CVE-2014-1529)

  - Cross-site scripting (XSS) using history navigations.
    (MFSA 2014-43 / CVE-2014-1530)

  - Use-after-free in imgLoader while resizing images. (MFSA
    2014-44 / CVE-2014-1531)

  - Use-after-free in nsHostResolver Mozilla NSS has been
    updated to 3.16:. (MFSA 2014-46 / CVE-2014-1532)

  - required for Firefox 29

  - In a wildcard certificate, the wildcard character should
    not be embedded within the U-label of an
    internationalized domain name. See the last bullet point
    in RFC 6125, Section 7.2. (CVE-2014-1492)

  - Update of root certificates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1520.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1523.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1524.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1532.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9185.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-24.5.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-branding-SLED-24-0.7.36")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-24.5.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libfreebl3-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libsoftokn3-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nspr-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-tools-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-24.5.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-24-0.7.36")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-24.5.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-tools-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-24.5.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-branding-SLED-24-0.7.36")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-24.5.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libfreebl3-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libsoftokn3-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nspr-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-tools-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libfreebl3-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libsoftokn3-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nss-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.16-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.16-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
