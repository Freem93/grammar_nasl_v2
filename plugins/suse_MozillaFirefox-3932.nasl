#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29361);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3285", "CVE-2007-3656", "CVE-2007-3670", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 3932)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to security update version 2.0.0.5

Following security problems were fixed :

  - Crashes with evidence of memory corruption The usual
    collection of stability fixes for crashes that look
    suspicious but haven't been proven to be exploitable.
    (MFSA 2007-18)

    25 were in the browser engine, reported by Mozilla
    developers and community members Bernd Mielke, Boris
    Zbarsky, David Baron, Daniel Veditz, Jesse Ruderman,
    Lukas Loehrer, Martijn Wargers, Mats Palmgren, Olli
    Pettay, Paul Nickerson,and Vladimir Sukhoy.
    (CVE-2007-3734)

    7 were in the JavaScript engine reported by Asaf Romano,
    Jesse Ruderman, Igor Bukanov. (CVE-2007-3735)

  - XSS using addEventListener and setTimeout. (MFSA 2007-19
    / CVE-2007-3736)

    moz_bug_r_a4 reported that scripts could be injected
    into another site's context by exploiting a timing issue
    using addEventLstener or setTimeout.

  - frame spoofing Ronen Zilberman and Michal Zalewski both
    reported that it was possible to exploit a timing issue
    to inject content into about:blank frames in a page.
    (MFSA 2007-20 / CVE-2007-3089)

  - Privilege escallation using an event handler attached to
    an element not in the document. (MFSA 2007-21 /
    CVE-2007-3737)

    Reported by moz_bug_r_a4.

  - File type confusion due to %00 in name. (MFSA 2007-22 /
    CVE-2007-3285)

    Ronald van den Heetkamp reported that a filename URL
    containing %00 (encoded null) can cause Firefox to
    interpret the file extension differently than the
    underlying Windows operating system potentially leading
    to unsafe actions such as running a program.

  - Remote code execution by launching Firefox from Internet
    Explorer. (MFSA 2007-23 / CVE-2007-3670)

    Greg MacManus of iDefense and Billy Rios of Verisign
    independently reported that links containing a quote (')
    character could be used in Internet Explorer to launch
    registered URL Protocol handlers with extra command-line
    parameters. Firefox and Thunderbird are among those
    which can be launched, and both support a '-chrome'
    option that could be used to run malware.

    This problem does not affect Linux.

  - unauthorized access to wyciwyg:// documents. (MFSA
    2007-24 / CVE-2007-3656)

    Michal Zalewski reported that it was possible to bypass
    the same-origin checks and read from cached (wyciwyg)
    documents

  - XPCNativeWrapper pollution shutdown and moz_bug_r_a4
    reported two separate ways to modify an XPCNativeWrapper
    such that subsequent access by the browser would result
    in executing user-supplied code. (MFSA 2007-25 /
    CVE-2007-3738)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3285.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3656.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3670.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3735.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3738.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3932.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-2.0.0.5-1.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-translations-2.0.0.5-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-2.0.0.5-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-translations-2.0.0.5-1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
