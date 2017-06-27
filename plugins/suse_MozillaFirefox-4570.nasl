#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29362);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2006-2894", "CVE-2006-4965", "CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-3845", "CVE-2007-4841", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 4570)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to security update version 2.0.0.8

Following security problems were fixed :

  - Privilege escalation through chrome-loaded about:blank
    windows. (MFSA 2007-26 / CVE-2007-3844)

    Mozilla researcher moz_bug_r_a4 reported that a flaw was
    introduced by the fix for MFSA 2007-20 that could enable
    privilege escalation attacks against addons that create
    'about:blank' windows and populate them in certain ways
    (including implicit 'about:blank' document creation
    through data: or javascript: URLs in a new window).

  - Crashes with evidence of memory corruption As part of
    the Firefox 2.0.0.8 update releases Mozilla developers
    fixed many bugs to improve the stability of the product.
    Some of these crashes showed evidence of memory
    corruption under certain circumstances and we presume
    that with enough effort at least some of these could be
    exploited to run arbitrary code. (MFSA 2007-29)

  - Browser crashes. (CVE-2007-5339)

  - JavaScript engine crashes. (CVE-2007-5340)

  - onUnload Tailgating Michal Zalewski demonstrated that
    onUnload event handlers had access to the address of the
    new page about to be loaded, even if the navigation was
    triggered from outside the page content such as by using
    a bookmark, pressing the back button, or typing an
    address into the location bar. If the bookmark contained
    sensitive information in the URL the attacking page
    might be able to take advantage of it. An attacking page
    would also be able to redirect the user, perhaps to a
    phishing page that looked like the site the user thought
    they were about to visit. (MFSA 2007-30 / CVE-2007-1095)

  - Digest authentication request splitting. (MFSA 2007-31 /
    CVE-2007-2292)

    Security researcher Stefano Di Paola reported that
    Firefox did not properly validate the user ID when
    making an HTTP request using Digest Authentication to
    log into a website. A malicious page could abuse this to
    inject arbitrary HTTP headers by including a newline
    character in the user ID followed by the injected header
    data. If the user were connecting through a proxy the
    attacker could inject headers that a proxy would
    interpret as two separate requests for different hosts.

  - File input focus stealing vulnerability. (MFSA 2007-32 /
    CVE-2007-3511 / CVE-2006-2894)

    A user on the Sla.ckers.org forums named hong reported
    that a file upload control could be filled
    programmatically by switching page focus to the label
    before a file upload form control for selected keyboard
    events. An attacker could use this trick to steal files
    from the users' computer if the attacker knew the full
    pathnames to the desired fileis and could create a
    pretext that would convince the user to type long enough
    to produce all the necessary characters.

  - XUL pages can hide the window titlebar. (MFSA 2007-33 /
    CVE-2007-5334)

    Mozilla developer Eli Friedman discovered that web pages
    written in the XUL markup language (rather than the
    usual HTML) can hide their window's titlebar. It may
    have been possible to abuse this ability to create more
    convincing spoof and phishing pages.

  - Possible file stealing through sftp protocol. (MFSA
    2007-34 / CVE-2007-5337)

    On Linux machines with gnome-vfs support the smb: and
    sftp: URI schemes are available in Firefox. Georgi
    Guninski showed that if an attacker can store the attack
    page in a mutually accessible location on the target
    server (/tmp perhaps) and lure the victim into loading
    it, the attacker could potentially read any file owned
    by the victim from known locations on that server.

  - XPCNativeWraper pollution using Script object. (MFSA
    2007-35 / CVE-2007-5338)

    Mozilla security researcher moz_bug_r_a4 reported that
    it was possible to use the Script object to modify
    XPCNativeWrappers in such a way that subsequent access
    by the browser chrome--such as by right-clicking to open
    a context menu--can cause attacker-supplied JavaScript
    to run with the same privileges as the user. This is
    similar to MFSA 2007-25 fixed in Firefox 2.0.0.5

Only Windows is affected by :

  - Unescaped URIs passed to external programs. (MFSA
    2007-27 / CVE-2007-3845)

    This problem affects Windows only due to their handling
    of URI launchers.

  - Code execution via QuickTime Media-link files. (MFSA
    2007-28 / CVE-2006-4965)

    Linux does not have .lnk files, nor Quicktime. Not
    affected.

  - URIs with invalid %-encoding mishandled by Windows.
    (MFSA 2007-36 / CVE-2007-4841)

    This problem does not affected Linux."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-2894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4965.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-1095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2292.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3845.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5334.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5337.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5338.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5340.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4570.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 94, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/19");
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
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-2.0.0.8-1.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-translations-2.0.0.8-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-2.0.0.8-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-translations-2.0.0.8-1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
