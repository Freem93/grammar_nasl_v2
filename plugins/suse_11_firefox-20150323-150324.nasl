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
  script_id(82068);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/05 04:38:20 $");

  script_cve_id("CVE-2015-0817", "CVE-2015-0818");

  script_name(english:"SuSE 11.3 Security Update : Mozilla Firefox (SAT Patch Number 10524)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 31.5.3ESR release to fix two
security vulnerabilities :

  - Security researcher ilxu1a reported, through HP Zero Day
    Initiative's Pwn2Own contest, a flaw in Mozilla's
    implementation of typed array bounds checking in
    JavaScript just-in-time compilation (JIT) and its
    management of bounds checking for heap access. This flaw
    can be leveraged into the reading and writing of memory
    allowing for arbitary code execution on the local
    system. (MFSA 2015-29 / CVE-2015-0817)

  - Security researcher Mariusz Mlynski reported, through HP
    Zero Day Initiative's Pwn2Own contest, a method to run
    arbitrary scripts in a privileged context. This bypassed
    the same-origin policy protections by using a flaw in
    the processing of SVG format content navigation. (MFSA
    2015-28 / CVE-2015-0818)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2015/mfsa2015-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2015/mfsa2015-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=923534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0818.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10524.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-31.5.3esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-31.5.3esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-31.5.3esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-31.5.3esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-31.5.3esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-31.5.3esr-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
