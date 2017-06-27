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
  script_id(82739);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/14 15:20:34 $");

  script_cve_id("CVE-2015-0801", "CVE-2015-0807", "CVE-2015-0813", "CVE-2015-0814", "CVE-2015-0815", "CVE-2015-0816");

  script_name(english:"SuSE 11.3 Security Update : Mozilla Firefox (SAT Patch Number 10571)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 31.6.0 ESR to fix five security issues.

The following vulnerabilities have been fixed :

  - Miscellaneous memory safety hazards. (MFSA 2015-30 /
    CVE-2015-0814 / CVE-2015-0815)

  - Use-after-free when using the Fluendo MP3 GStreamer
    plugin. (MFSA 2015-31 / CVE-2015-0813)

  - resource:// documents can load privileged pages. (MFSA
    2015-33 / CVE-2015-0816)

  - CORS requests should not follow 30x redirections after
    preflight. (MFSA 2015-37 / CVE-2015-0807)

  - Same-origin bypass through anchor navigation (MFSA
    2015-40 / CVE-2015-0801)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2015/mfsa2015-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=925368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0814.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0816.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10571.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox PDF.js Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-31.6.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-31.6.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-31.6.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-31.6.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-31.6.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-31.6.0esr-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
