# @DEPRECATED@
#
# This script has been deprecated as the associated update is not
# for a supported release of Mandrake / Mandriva Linux.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKSA-2005:120-1.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(20420);
  script_version ("$Revision: 1.11 $"); 
  script_cvs_date("$Date: 2012/09/07 00:48:07 $");

  script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");

  script_name(english:"MDKSA-2005:120-1 : mozilla-firefox");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A number of vulnerabilities were reported and fixed in Firefox 1.0.5
and Mozilla 1.7.9. The following vulnerabilities have been backported
and patched for this update:

In several places the browser UI did not correctly distinguish
between true user events, such as mouse clicks or keystrokes, and
synthetic events genenerated by web content. The problems ranged from
minor annoyances like switching tabs or entering full-screen mode, to
a variant on MFSA 2005-34 Synthetic events are now prevented from
reaching the browser UI entirely rather than depend on each
potentially spoofed function to protect itself from untrusted events
(MFSA 2005-45; CVE-2005-2260).

Scripts in XBL controls from web content continued to be run even
when Javascript was disabled. By itself this causes no harm, but it
could be combined with most script-based exploits to attack people
running vulnerable versions who thought disabling javascript would
protect them. In the Thunderbird and Mozilla Suite mail clients
Javascript is disabled by default for protection against
denial-of-service attacks and worms; this vulnerability could be used
to bypass that protection (MFSA 2005-46; CVE-2005-2261).

If an attacker can convince a victim to use the 'Set As Wallpaper'
context menu item on a specially crafted image then they can run
arbitary code on the user's computer. The image 'source' must be a
javascript: url containing an eval() statement and such an image
would get the 'broken image' icon, but with CSS it could be made
transparent and placed on top of a real image. The attacker would
have to convince the user to change their desktop background to the
exploit image, and to do so by using the Firefox context menu rather
than first saving the image locally and using the normal mechanism
provided by their operating system. This affects only Firefox 1.0.3
and 1.0.4; earlier versions are unaffected. The implementation of
this feature in the Mozilla Suite is also unaffected (MFSA 2005-47;
CVE-2005-2262).

The InstallTrigger.install() method for launching an install accepts
a callback function that will be called with the final success or
error status. By forcing a page navigation immediately after calling
the install method this callback function can end up running in the
context of the new page selected by the attacker. This is true even
if the user cancels the unwanted install dialog: cancel is an error
status. This callback script can steal data from the new page such as
cookies or passwords, or perform actions on the user's behalf such as
make a purchase if the user is already logged into the target site.
In Firefox the default settings allow only http://addons.mozilla.org
to bring up this install dialog. This could only be exploited if
users have added questionable sites to the install whitelist, and if
a malicious site can convince you to install from their site that's a
much more powerful attack vector. In the Mozilla Suite the whitelist
feature is turned off by default, any site can prompt the user to
install software and exploit this vulnerability. The browser has been
fixed to clear any pending callback function when switching to a new
site (MFSA 2005-48; CVE-2005-2263).

Sites can use the _search target to open links in the Firefox
sidebar. A missing security check allows the sidebar to inject data:
urls containing scripts into any page open in the browser. This could
be used to steal cookies, passwords or other sensitive data (MFSA
2005-49; CVE-2005-2264).

When InstallVersion.compareTo() is passed an object rather than a
string it assumed the object was another InstallVersion without
verifying it. When passed a different kind of object the browser
would generally crash with an access violation. shutdown has
demonstrated that different javascript objects can be passed on some
OS versions to get control over the instruction pointer. We assume
this could be developed further to run arbitrary machine code if the
attacker can get exploit code loaded at a predictable address (MFSA
2005-50; CVE-2005-2265).

The original frame-injection spoofing bug was fixed in the Mozilla
Suite 1.7 and Firefox 0.9 releases. This protection was accidentally
bypassed by one of the fixes in the Firefox 1.0.3 and Mozilla Suite
1.7.7 releases (MFSA 2005-51; CVE-2005-1937).

A child frame can call top.focus() even if the framing page comes
from a different origin and has overridden the focus() routine. The
call is made in the context of the child frame. The attacker would
look for a target site with a framed page that makes this call but
doesn't verify that its parent comes from the same site. The attacker
could steal cookies and passwords from the framed page, or take
actions on behalf of a signed-in user. This attack would work only
against sites that use frames in this manner (MFSA 2005-52;
CVE-2005-2266).

Several media players, for example Flash and QuickTime, support
scripted content with the ability to open URLs in the default
browser. The default behavior for Firefox was to replace the
currently open browser window's content with the externally opened
content. If the external URL was a javascript: url it would run as if
it came from the site that served the previous content, which could
be used to steal sensitive information such as login cookies or
passwords. If the media player content first caused a privileged
chrome: url to load then the subsequent javascript: url could execute
arbitrary code. External javascript: urls will now run in a blank
context regardless of what content it's replacing, and external apps
will no longer be able to load privileged chrome: urls in a browser
window. The -chrome command line option to load chrome applications
is still supported (MFSA 2005-53; CVE-2005-2267).

Alerts and prompts created by scripts in web pages are presented with
the generic title [JavaScript Application] which sometimes makes it
difficult to know which site created them. A malicious page could
attempt to cause a prompt to appear in front of a trusted site in an
attempt to extract information such as passwords from the user. In
the fixed version these prompts will contain the hostname from the
page which created it (MFSA 2005-54; CVE-2005-2268).

Parts of the browser UI relied too much on DOM node names without
taking different namespaces into account and verifying that nodes
really were of the expected type. An XHTML document could be used to
create fake elements, for example, with content-defined properties
that the browser would access as if they were the trusted built-in
properties of the expected HTML elements. The severity of the
vulnerability would depend on what the attacker could convince the
victim to do, but could result in executing user-supplied script with
elevated 'chrome' privileges. This could be used to install malicious
software on the victim's machine (MFSA 2005-55; CVE-2005-2269).

Improper cloning of base objects allowed web content scripts to walk
up the prototype chain to get to a privileged object. This could be
used to execute code with enhanced privileges (MFSA 2005-56;
CVE-2005-2270).

The updated packages have been patched to address these issue.

Update:

New packages are available that fix some regression errors that
appeared in the Firefox 1.0.5 release that the patches were based on.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKSA-2005:120-1");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox InstallVersion->compareTo() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/15");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated update is not currently for a supported release of Mandrake / Mandriva Linux.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"libnspr4-1.0.2-8.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libnspr4-devel-1.0.2-8.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libnss3-1.0.2-8.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libnss3-devel-1.0.2-8.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"mozilla-firefox-1.0.2-8.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"mozilla-firefox-devel-1.0.2-8.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  if (rpm_exists(rpm:"mozilla-firefox-", release:"MDK10.2"))
  {
    set_kb_item(name:"CVE-2005-1937", value:TRUE);
    set_kb_item(name:"CVE-2005-2260", value:TRUE);
    set_kb_item(name:"CVE-2005-2261", value:TRUE);
    set_kb_item(name:"CVE-2005-2262", value:TRUE);
    set_kb_item(name:"CVE-2005-2263", value:TRUE);
    set_kb_item(name:"CVE-2005-2264", value:TRUE);
    set_kb_item(name:"CVE-2005-2265", value:TRUE);
    set_kb_item(name:"CVE-2005-2266", value:TRUE);
    set_kb_item(name:"CVE-2005-2267", value:TRUE);
    set_kb_item(name:"CVE-2005-2268", value:TRUE);
    set_kb_item(name:"CVE-2005-2269", value:TRUE);
    set_kb_item(name:"CVE-2005-2270", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
