#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-978-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49269);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-2760", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_bugtraq_id(43091, 43093, 43094, 43095, 43097, 43100, 43101, 43102, 43104, 43106, 43108, 43118);
  script_xref(name:"USN", value:"978-2");

  script_name(english:"Ubuntu 10.04 LTS : thunderbird regression (USN-978-2)");
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
"USN-978-1 fixed vulnerabilities in Thunderbird. Some users reported
stability problems under certain circumstances. This update fixes the
problem.

We apologize for the inconvenience.

Several dangling pointer vulnerabilities were discovered in
Thunderbird. An attacker could exploit this to crash Thunderbird or
possibly run arbitrary code as the user invoking the program.
(CVE-2010-2760, CVE-2010-2767, CVE-2010-3167)

It was discovered that the XPCSafeJSObjectWrapper (SJOW)
security wrapper did not always honor the same-origin
policy. If JavaScript was enabled, an attacker could exploit
this to run untrusted JavaScript from other domains.
(CVE-2010-2763)

Matt Haggard discovered that Thunderbird did not honor
same-origin policy when processing the statusText property
of an XMLHttpRequest object. If a user were tricked into
viewing a malicious site, a remote attacker could use this
to gather information about servers on internal private
networks. (CVE-2010-2764)

Chris Rohlf discovered an integer overflow when Thunderbird
processed the HTML frameset element. If a user were tricked
into viewing a malicious site, a remote attacker could use
this to crash Thunderbird or possibly run arbitrary code as
the user invoking the program. (CVE-2010-2765)

Several issues were discovered in the browser engine. If a
user were tricked into viewing a malicious site, a remote
attacker could use this to crash Thunderbird or possibly run
arbitrary code as the user invoking the program.
(CVE-2010-2766, CVE-2010-3168)

David Huang and Collin Jackson discovered that the <object>
tag could override the charset of a framed HTML document in
another origin. An attacker could utilize this to perform
cross-site scripting attacks. (CVE-2010-2768)

Paul Stone discovered that with designMode enabled an HTML
selection containing JavaScript could be copied and pasted
into a document and have the JavaScript execute within the
context of the site where the code was dropped. If
JavaScript was enabled, an attacker could utilize this to
perform cross-site scripting attacks. (CVE-2010-2769)

A buffer overflow was discovered in Thunderbird when
processing text runs. If a user were tricked into viewing a
malicious site, a remote attacker could use this to crash
Thunderbird or possibly run arbitrary code as the user
invoking the program. (CVE-2010-3166)

Peter Van der Beken, Jason Oster, Jesse Ruderman, Igor
Bukanov, Jeff Walden, Gary Kwong and Olli Pettay discovered
several flaws in the browser engine. If a user were tricked
into viewing a malicious site, a remote attacker could use
this to crash Thunderbird or possibly run arbitrary code as
the user invoking the program. (CVE-2010-3169).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dbg", pkgver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dev", pkgver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support", pkgver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support-dbg", pkgver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-dbg / thunderbird-dev / etc");
}
