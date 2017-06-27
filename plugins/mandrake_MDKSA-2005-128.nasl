#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:128. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19888);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270", "CVE-2005-2271", "CVE-2005-2272", "CVE-2005-2273", "CVE-2005-2274");
  script_xref(name:"MDKSA", value:"2005:128");

  script_name(english:"Mandrake Linux Security Advisory : mozilla (MDKSA-2005:128)");
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
"A number of vulnerabilities were reported and fixed in Mozilla 1.7.9.
The following vulnerabilities have been backported and patched for
this update :

In several places the browser UI did not correctly distinguish between
true user events, such as mouse clicks or keystrokes, and synthetic
events genenerated by web content. The problems ranged from minor
annoyances like switching tabs or entering full-screen mode, to a
variant on MFSA 2005-34 Synthetic events are now prevented from
reaching the browser UI entirely rather than depend on each
potentially spoofed function to protect itself from untrusted events
(MFSA 2005-45).

Scripts in XBL controls from web content continued to be run even when
JavaScript was disabled. By itself this causes no harm, but it could
be combined with most script-based exploits to attack people running
vulnerable versions who thought disabling JavaScript would protect
them. In the Thunderbird and Mozilla Suite mail clients JavaScript is
disabled by default for protection against denial-of-service attacks
and worms; this vulnerability could be used to bypass that protection
(MFSA 2005-46).

The InstallTrigger.install() method for launching an install accepts a
callback function that will be called with the final success or error
status. By forcing a page navigation immediately after calling the
install method this callback function can end up running in the
context of the new page selected by the attacker. This is true even if
the user cancels the unwanted install dialog: cancel is an error
status. This callback script can steal data from the new page such as
cookies or passwords, or perform actions on the user's behalf such as
make a purchase if the user is already logged into the target site. In
Firefox the default settings allow only http://addons.mozilla.org to
bring up this install dialog. This could only be exploited if users
have added questionable sites to the install whitelist, and if a
malicious site can convince you to install from their site that's a
much more powerful attack vector. In the Mozilla Suite the whitelist
feature is turned off by default, any site can prompt the user to
install software and exploit this vulnerability. The browser has been
fixed to clear any pending callback function when switching to a new
site (MFSA 2005-48).

When InstallVersion.compareTo() is passed an object rather than a
string it assumed the object was another InstallVersion without
verifying it. When passed a different kind of object the browser would
generally crash with an access violation. shutdown has demonstrated
that different JavaScript objects can be passed on some OS versions to
get control over the instruction pointer. We assume this could be
developed further to run arbitrary machine code if the attacker can
get exploit code loaded at a predictable address (MFSA 2005-50).

The original frame-injection spoofing bug was fixed in the Mozilla
Suite 1.7 and Firefox 0.9 releases. This protection was accidentally
bypassed by one of the fixes in the Firefox 1.0.3 and Mozilla Suite
1.7.7 releases (MFSA 2005-51).

A child frame can call top.focus() even if the framing page comes from
a different origin and has overridden the focus() routine. The call is
made in the context of the child frame. The attacker would look for a
target site with a framed page that makes this call but doesn't verify
that its parent comes from the same site. The attacker could steal
cookies and passwords from the framed page, or take actions on behalf
of a signed-in user. This attack would work only against sites that
use frames in this manner (MFSA 2005-52).

Alerts and prompts created by scripts in web pages are presented with
the generic title [JavaScript Application] which sometimes makes it
difficult to know which site created them. A malicious page could
attempt to cause a prompt to appear in front of a trusted site in an
attempt to extract information such as passwords from the user. In the
fixed version these prompts will contain the hostname from the page
which created it (MFSA 2005-54).

Parts of the browser UI relied too much on DOM node names without
taking different namespaces into account and verifying that nodes
really were of the expected type. An XHTML document could be used to
create fake <IMG> elements, for example, with content-defined
properties that the browser would access as if they were the trusted
built-in properties of the expected HTML elements. The severity of the
vulnerability would depend on what the attacker could convince the
victim to do, but could result in executing user-supplied script with
elevated 'chrome' privileges. This could be used to install malicious
software on the victim's machine (MFSA 2005-55).

Improper cloning of base objects allowed web content scripts to walk
up the prototype chain to get to a privileged object. This could be
used to execute code with enhanced privileges (MFSA 2005-56).

The updated packages have been patched to address these issue. This
update also brings the mozilla shipped in Mandriva Linux 10.1 to
version 1.7.8 to ease maintenance. As a result, new galeon and
epiphany packages are also available for 10.1, and community contribs
packages that are built against mozilla have been rebuilt and are also
available via contribs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/15489/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/15549/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/15601/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-56.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-spellchecker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
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
if (rpm_check(release:"MDK10.1", reference:"epiphany-1.2.8-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"epiphany-devel-1.2.8-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"galeon-1.3.17-3.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nspr4-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nspr4-devel-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nss3-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nss3-devel-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnspr4-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnspr4-devel-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnss3-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnss3-devel-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-devel-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-dom-inspector-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-enigmail-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-enigmime-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-irc-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-js-debugger-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-mail-1.7.8-0.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-spellchecker-1.7.8-0.2.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
