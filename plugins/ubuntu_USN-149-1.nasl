#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-149-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20544);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
  script_xref(name:"USN", value:"149-1");

  script_name(english:"Ubuntu 5.04 : mozilla-firefox vulnerabilities (USN-149-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Secunia.com reported that one of the recent security patches in
Firefox reintroduced the frame injection patch that was originally
known as CAN-2004-0718. This allowed a malicious website to spoof the
contents of other websites. (CAN-2005-1937)

In several places the browser user interface did not correctly
distinguish between true user events, such as mouse clicks or
keystrokes, and synthetic events genenerated by web content. This
could be exploited by malicious websites to generate e. g. mouse
clicks that install malicious plugins. Synthetic events are now
prevented from reaching the browser UI entirely. (CAN-2005-2260)

Scripts in XBL controls from web content continued to be run even when
JavaScript was disabled. This could be combined with most script-based
exploits to attack people running vulnerable versions who thought
disabling JavaScript would protect them. (CAN-2005-2261)

Matthew Mastracci discovered a flaw in the addons installation
launcher. By forcing a page navigation immediately after calling the
install method a callback function could end up running in the context
of the new page selected by the attacker. This callback script could
steal data from the new page such as cookies or passwords, or perform
actions on the user's behalf such as make a purchase if the user is
already logged into the target site. However, the default settings
allow only http://addons.mozilla.org to bring up this install dialog.
This could only be exploited if users have added untrustworthy sites
to the installation whitelist, and if a malicious site can convince
you to install from their site. (CAN-2005-2263)

Kohei Yoshino discovered a JavaScript injection vulnerability in the
sidebar. Sites can use the _search target to open links in the Firefox
sidebar. A missing security check allowed the sidebar to inject
'data:' URLs containing scripts into any page open in the browser.
This could be used to steal cookies, passwords or other sensitive
data. (CAN-2005-2264)

The function for version comparison in the addons installer did not
properly verify the type of its argument. By passing specially crafted
JavaScript objects to it, a malicious website could crash the browser
and possibly even execute arbitrary code with the privilege of the
user account Firefox runs in. (CAN-2005-2265)

A child frame can call top.focus() even if the framing page comes from
a different origin and has overridden the focus() routine. Andreas
Sandblad discovered that the call is made in the context of the child
frame. This could be exploited to steal cookies and passwords from the
framed page, or take actions on behalf of a signed-in user. However,
websites with above properties are not very common. (CAN-2005-2266)

Several media players, for example Flash and QuickTime, support
scripted content with the ability to open URLs in the default browser.
The default behavior for Firefox was to replace the currently open
browser window's content with the externally opened content. Michael
Krax discovered that if the external URL was a javascript: URL it
would run as if it came from the site that served the previous
content, which could be used to steal sensitive information such as
login cookies or passwords. If the media player content first caused a
privileged chrome: url to load then the subsequent javascript: url
could execute arbitrary code. (CAN-2005-2267)

Alerts and prompts created by scripts in web pages were presented with
the generic title [JavaScript Application] which sometimes made it
difficult to know which site created them. A malicious page could
exploit this by causing a prompt to appear in front of a trusted site
in an attempt to extract information such as passwords from the user.
In the fixed version these prompts contain the hostname of the page
which created it. (CAN-2005-2268)

The XHTML DOM node handler did not take namespaces into account when
verifying node types based on their names. For example, an XHTML
document could contain an <IMG> tag with malicious contents, which
would then be processed as the standard trusted HTML <img> tag. By
tricking an user to view malicious websites, this could be exploited
to execute attacker-specified code with the full privileges of the
user. (CAN-2005-2269)

It was discovered that some objects were not created appropriately.
This allowed malicious web content scripts to trace back the creation
chain until they found a privileged object and execute code with
higher privileges than allowed by the current site. (CAN-2005-2270).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox", pkgver:"1.0.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-dev", pkgver:"1.0.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-dom-inspector", pkgver:"1.0.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-gnome-support", pkgver:"1.0.2-0ubuntu5.4")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-firefox / mozilla-firefox-dev / etc");
}
