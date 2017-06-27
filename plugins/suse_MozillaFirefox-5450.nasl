#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33757);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 5450)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to version 2.0.0.16, which fixes various
bugs and following security issues :

  - An anonymous researcher, via TippingPoint's Zero Day
    Initiative program, reported a vulnerability in Mozilla
    CSS reference counting code. The vulnerability was
    caused by an insufficiently sized variable being used as
    a reference counter for CSS objects. By creating a very
    large number of references to a common CSS object, this
    counter could be overflowed which could cause a crash
    when the browser attempts to free the CSS object while
    still in use. An attacker could use this crash to run
    arbitrary code on the victim's computer. (MFSA 2008-34 /
    CVE-2008-2785)

  - Security researcher Billy Rios reported that if Firefox
    is not already running, passing it a command-line URI
    with pipe symbols will open multiple tabs. This URI
    splitting could be used to launch privileged chrome:
    URIs from the command-line, a partial bypass of the fix
    for MFSA 2005-53 which blocks external applications from
    loading such URIs. This vulnerability could also be used
    by an attacker to launch a file: URI from the command
    line opening a malicious local file which could
    exfiltrate data from the local filesystem. Combined with
    a vulnerability which allows an attacker to inject code
    into a chrome document, the above issue could be used to
    run arbitrary code on a victim's computer. Such a chrome
    injection vulnerability was reported by Mozilla
    developers Ben Turner and Dan Veditz who showed that a
    XUL based SSL error page was not properly sanitizing
    inputs and could be used to run arbitrary code with
    chrome privileges. (MFSA 2008-35 / CVE-2008-2933)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2005/mfsa2005-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2785.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2933.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5450.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-2.0.0.16-0.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-translations-2.0.0.16-0.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-2.0.0.16-0.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-translations-2.0.0.16-0.4")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-2.0.0.16-0.3.1")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-translations-2.0.0.16-0.3.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-2.0.0.16-0.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-translations-2.0.0.16-0.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
