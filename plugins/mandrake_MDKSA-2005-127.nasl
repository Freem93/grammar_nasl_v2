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
# Mandrake Linux Security Advisory MDKSA-2005:127-1.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(20421);
  script_version ("$Revision: 1.11 $"); 
  script_cvs_date("$Date: 2012/09/07 00:48:07 $");

  script_cve_id("CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");

  script_name(english:"MDKSA-2005:127-1 : mozilla-thunderbird");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A number of vulnerabilities were reported and fixed in Thunderbird
1.0.5 and Mozilla 1.7.9. The following vulnerabilities have been
backported and patched for this update:

The native implementations of InstallTrigger and other XPInstall-
related javascript objects did not properly validate that they were
called on instances of the correct type. By passing other objects,
even raw numbers, the javascript interpreter would jump to the wrong
place in memory. Although no proof of concept has been developed we
believe this could be exploited (MFSA 2005-40).

moz_bug_r_a4 reported several exploits giving an attacker the ability
to install malicious code or steal data, requiring only that the user
do commonplace actions like clicking on a link or open the context
menu. The common cause in each case was privileged UI code ('chrome')
being overly trusting of DOM nodes from the content window. Scripts
in the web page can override properties and methods of DOM nodes and
shadow the native values, unless steps are taken to get the true
underlying values (MFSA 2005-41).

Additional checks were added to make sure Javascript eval and Script
objects are run with the privileges of the context that created them,
not the potentially elevated privilege of the context calling them in
order to protect against an additional variant of MFSA 2005-41 (MFSA
2005-44).

In several places the browser UI did not correctly distinguish
between true user events, such as mouse clicks or keystrokes, and
synthetic events genenerated by web content. The problems ranged from
minor annoyances like switching tabs or entering full-screen mode, to
a variant on MFSA 2005-34 Synthetic events are now prevented from
reaching the browser UI entirely rather than depend on each
potentially spoofed function to protect itself from untrusted events
(MFSA 2005-45).

Scripts in XBL controls from web content continued to be run even
when Javascript was disabled. By itself this causes no harm, but it
could be combined with most script-based exploits to attack people
running vulnerable versions who thought disabling javascript would
protect them. In the Thunderbird and Mozilla Suite mail clients
Javascript is disabled by default for protection against
denial-of-service attacks and worms; this vulnerability could be used
to bypass that protection (MFSA 2005-46).

When InstallVersion.compareTo() is passed an object rather than a
string it assumed the object was another InstallVersion without
verifying it. When passed a different kind of object the browser
would generally crash with an access violation. shutdown has
demonstrated that different javascript objects can be passed on some
OS versions to get control over the instruction pointer. We assume
this could be developed further to run arbitrary machine code if the
attacker can get exploit code loaded at a predictable address (MFSA
2005-50).

A child frame can call top.focus() even if the framing page comes
from a different origin and has overridden the focus() routine. The
call is made in the context of the child frame. The attacker would
look for a target site with a framed page that makes this call but
doesn't verify that its parent comes from the same site. The attacker
could steal cookies and passwords from the framed page, or take
actions on behalf of a signed-in user. This attack would work only
against sites that use frames in this manner (MFSA 2005-52).

Parts of the browser UI relied too much on DOM node names without
taking different namespaces into account and verifying that nodes
really were of the expected type. An XHTML document could be used to
create fake elements, for example, with content-defined properties
that the browser would access as if they were the trusted built-in
properties of the expected HTML elements. The severity of the
vulnerability would depend on what the attacker could convince the
victim to do, but could result in executing user-supplied script with
elevated 'chrome' privileges. This could be used to install malicious
software on the victim's machine (MFSA 2005-55).

Improper cloning of base objects allowed web content scripts to walk
up the prototype chain to get to a privileged object. This could be
used to execute code with enhanced privileges (MFSA 2005-56).

The updated packages have been patched to address these issue.

Update:

There was a slight regression in the handling of 'right-click' menus
in the packages previously released that is corrected with this new
update.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKSA-2005:127-1");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox InstallVersion->compareTo() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/26");
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

if (rpm_check(reference:"mozilla-thunderbird-1.0.2-3.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-devel-1.0.2-3.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-1.0.2-3.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmime-1.0.2-3.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  if (rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK10.2"))
  {
    set_kb_item(name:"CVE-2005-2260", value:TRUE);
    set_kb_item(name:"CVE-2005-2261", value:TRUE);
    set_kb_item(name:"CVE-2005-2265", value:TRUE);
    set_kb_item(name:"CVE-2005-2266", value:TRUE);
    set_kb_item(name:"CVE-2005-2269", value:TRUE);
    set_kb_item(name:"CVE-2005-2270", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
