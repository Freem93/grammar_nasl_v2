#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(41467);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1169");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 6187)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox Browser was refreshed to the current MOZILLA_1_8
branch state around fix level 2.0.0.22. 

Security issues identified as being fixed are: MFSA 2009-01 /
CVE-2009-0352 / CVE-2009-0353: Mozilla developers identified and fixed
several stability bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these crashes showed evidence of
memory corruption under certain circumstances and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

  - Mozilla developers identified and fixed several
    stability bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these crashes
    showed evidence of memory corruption under certain
    circumstances and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2009-07 / CVE-2009-0772 / CVE-2009-0774)

  - Mozilla security researcher Georgi Guninski reported
    that a website could use nsIRDFService and a
    cross-domain redirect to steal arbitrary XML data from
    another domain, a violation of the same-origin policy.
    This vulnerability could be used by a malicious website
    to steal private data from users authenticated to the
    redirected website. (MFSA 2009-09 / CVE-2009-0776)

  - Google security researcher Tavis Ormandy reported
    several memory safety hazards to the libpng project, an
    external library used by Mozilla to render PNG images.
    These vulnerabilities could be used by a malicious
    website to crash a victim's browser and potentially
    execute arbitrary code on their computer. libpng was
    upgraded to version 1.2.35 which containis fixes for
    these flaws. (MFSA 2009-10 / CVE-2009-0040)

  - Security researcher Guido Landi discovered that a XSL
    stylesheet could be used to crash the browser during a
    XSL transformation. An attacker could potentially use
    this crash to run arbitrary code on a victim's computer.
    This vulnerability was also previously reported as a
    stability problem by Ubuntu community member, Andre.
    Ubuntu community member Michael Rooney reported Andre's
    findings to Mozilla, and Mozilla community member Martin
    helped reduce Andre's original testcase and contributed
    a patch to fix the vulnerability. (MFSA 2009-12 /
    CVE-2009-1169)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1169.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6187.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-2.0.0.21post-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-translations-2.0.0.21post-0.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-2.0.0.21post-0.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-translations-2.0.0.21post-0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
