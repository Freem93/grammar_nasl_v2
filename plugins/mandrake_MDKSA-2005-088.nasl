#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:088. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18277);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0527", "CVE-2005-0752", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160");
  script_xref(name:"MDKSA", value:"2005:088");

  script_name(english:"Mandrake Linux Security Advisory : mozilla (MDKSA-2005:088)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of security vulnerabilities were fixed in the Mozilla Firefox
1.0.4 and Mozilla Suite 1.7.8 releases. Patches have been backported
where appropriate; Corporate 3.0 is receiving the new Mozilla Suite
1.7.8 release.

The following issues have been fixed in both Mozilla Firefox and
Mozilla Suite :

  - A flaw in the JavaScript regular expression handling
    could lead to a disclosure of browser memory,
    potentially exposing private data from web pages viewed,
    passwords, or similar data sent to other web pages. It
    could also crash the browser itself (CVE-2005-0989, MFSA
    2005-33)

  - With manual Plugin install, it was possible for the
    Plugin to execute JavaScript code with the installing
    user's privileges (CVE-2005-0752 and MFSA 2005-34)

  - The popup for showing blocked JavaScript used the wrong
    privilege context which could be sued for privilege
    escalation (CVE-2005-1153 and MFSA 2005-35)

  - Cross-site scripting through global scope pollution
    could lead an attacker to being able to run code in
    foreign websites context, leading to the potential
    sniffing of information or performing actions in that
    context (CVE-2005-1154 and MFSA 2005-36)

  - Code execution through JavaScript via favicons
    ('firelinking') could be used for privilege escalation
    (CVE-2005-1155 and MFSA 2005-37)

  - Search plugin cross-site scripting ('firesearching')
    (CVE-2005-1156, CVE-2005-1157, and MFSA 2005-38)

  - Arbitrary code execution via the Firefox sidebar panel
    II (CVE-2005-1158 and MFSA 2005-39)

  - Missing Install object instance checks (CVE-2005-1159
    and MFSA 2005-40)

  - Privilege escalation via DOM property overrides
    (CVE-2005-1160 and MFSA 2005-41)

  - Code execution via javacript: IconURL (MFSA 2005-42)

  - Security check bypass by wrapping a javascript: URL in
    the view-source: pseudo protocol (MFSA 2005-43)

  - Privilege escalation via non-DOM property overrides
    (MFSA 2005-44)

In addition to the vulnerabilities previously noted, the following
issues have been fixed in the Mozilla Suite 1.7.2 packages :

  - Bypass restriction on opening privileged XUL
    (CVE-2005-0401 and MSF 2005-32)

  - Arbitrary code execution via a GIF processing error when
    parsing obsolete Netscape extension 2 leading to an
    exploitable heap overrun (CVE-2005-0401 and MFSA
    2005-32)

  - International Domain Name support could allow for
    characters that look similar to other english letters to
    be used in constructing nearly perfect phishing sites
    (MFSA 2005-29)

  - Predictable plugin temporary directory name (MFSA
    2005-28)

  - Plugins can be used to load privileged content into a
    frame (CVE-2005-0527 and MFSA 2005-27)

  - Cross-site scripting attack via dropping javascript:
    links on a tab (MFSA 2005-26)

  - Image dragging-and-drop from a web page to the desktop
    preserve their original name and extension; if this were
    an executable extension then the file would be executed
    rather than opened in a media application (MFSA 2005-25)

  - HTTP authentication prompt tab spoofing (MFSA 2005-24)

  - Download dialog source can be disguised by using a host
    name long enough that most significant parts are
    truncated, allowing a malicious site to spoof the origin
    of the file (MFSA 2005-23)

  - Download dialog spoofing via supplied
    Content-Disposition header could allow for a file to
    look like a safe file (ie. a JPEG image) and when
    downloaded saved with an executable extension (MFSA
    2005-22)

  - XSLT can include stylesheets from arbitrary hosts (MFSA
    2005-20)

  - Memory handling flaw in Mozilla string classes that
    could overwrite memory at a fixed location if
    reallocation fails during string growth (MFSA 2005-18)

  - Install source spoofing with user:pass@host (MFSA
    2005-17)

  - Spoofing download and security dialogs with overlapping
    windows (MFSA 2005-16)

  - It is possible for a UTF8 string with invalid sequences
    to trigger a heap overflow of converted Unicode data
    (MFSA 2005-15)

  - SSL 'secure site' indicator spoofing (MFSA 2005-14)

  - Mozilla mail clients responded to cookie requests
    accompanying content loaded over HTTP, ignoring the
    setting of the preference
    'network.cookie.disableCookieForMailNews' which could be
    used to track people (MFSA 2005-11)

  - Browser responds to proxy authentication requests from
    non-proxy servers (SSL/HTTPS) (MFSA 2005-09)

  - Snythetic middle-click event can steal clipboard
    contents (MFSA 2005-08)

  - In windows with multiple tabs, malicious content in a
    background tab can attempt to steal information intended
    for the topmost tab by popping up a prompt dialog that
    appears to come from the trusted site, or by silently
    redirecting input focus to a background tab hoping to
    catch the user inputting something sensitive (MFSA
    2005-05)

  - Secure site lock can be spoofed with 'view-source:'
    (MFSA 2005-04)

  - An insecure page triggering a load of a binary file from
    a secure server will cause the SSL lock icon to appear;
    the certificate information is that of the binary file's
    host and the location bar URL shows the original
    insecure page (MFSA 2005-03)

  - Temporary files are saved with world-readable
    permissions (MFSA 2005-02)

  - A vulnerability in the NNTP handling code could cause a
    heap overflow and execute arbitrary code on the client
    machine (isec-0020)

  - A number of other minor bugs were fixed as well.

Mandriva recommends all users to upgrade to these packages
immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0020-mozilla.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-40.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-41.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=290476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=290777"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-enigmime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-spellchecker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK10.1", reference:"epiphany-1.2.8-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"epiphany-devel-1.2.8-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"galeon-1.3.17-3.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nspr4-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nspr4-devel-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nss3-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nss3-devel-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnspr4-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnspr4-devel-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnss3-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnss3-devel-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-devel-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-dom-inspector-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-enigmail-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-enigmime-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-irc-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-js-debugger-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-mail-1.7.2-12.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-spellchecker-1.7.2-12.2.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"epiphany-1.4.8-8.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"epiphany-devel-1.4.8-8.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"galeon-1.3.19-7.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64nspr4-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64nspr4-devel-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64nss3-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64nss3-devel-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libnspr4-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libnspr4-devel-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libnss3-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libnss3-devel-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"mozilla-firefox-1.0.2-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"mozilla-firefox-devel-1.0.2-5.2.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
