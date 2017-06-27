#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62780);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/12/02 03:33:13 $");

  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 8348)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to the 10.0.10ESR security release.

The following issues have been fixed :

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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8348.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-10.0.10-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-translations-10.0.10-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nspr-4.9.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nspr-devel-4.9.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-10.0.10-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-translations-10.0.10-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nspr-4.9.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nspr-devel-4.9.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.3-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
