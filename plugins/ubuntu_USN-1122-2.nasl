#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1122-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55081);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");
  script_bugtraq_id(47641, 47646, 47647, 47648, 47651, 47653, 47654, 47655, 47656, 47659, 47662, 47663, 47666, 47667, 47668);
  script_xref(name:"USN", value:"1122-2");

  script_name(english:"Ubuntu 11.04 : thunderbird vulnerabilities (USN-1122-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1122-1 fixed vulnerabilities in Thunderbird for Lucid and
Maverick. This update provides the corresponding fixes for Natty.

It was discovered that there was a vulnerability in the memory
handling of certain types of content. An attacker could exploit this
to possibly run arbitrary code as the user running Thunderbird.
(CVE-2011-0081)

It was discovered that Thunderbird incorrectly handled
certain JavaScript requests. If JavaScript were enabled, an
attacker could exploit this to possibly run arbitrary code
as the user running Thunderbird. (CVE-2011-0069)

Ian Beer discovered a vulnerability in the memory handling
of a certain types of documents. An attacker could exploit
this to possibly run arbitrary code as the user running
Thunderbird. (CVE-2011-0070)

Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren and
Jesse Ruderman discovered several memory vulnerabilities. An
attacker could exploit these to possibly run arbitrary code
as the user running Thunderbird. (CVE-2011-0080)

Aki Helin discovered multiple vulnerabilities in the HTML
rendering code. An attacker could exploit these to possibly
run arbitrary code as the user running Thunderbird.
(CVE-2011-0074, CVE-2011-0075)

Ian Beer discovered multiple overflow vulnerabilities. An
attacker could exploit these to possibly run arbitrary code
as the user running Thunderbird. (CVE-2011-0077,
CVE-2011-0078)

Martin Barbella discovered a memory vulnerability in the
handling of certain DOM elements. An attacker could exploit
this to possibly run arbitrary code as the user running
Thunderbird. (CVE-2011-0072)

It was discovered that there were use-after-free
vulnerabilities in Thunderbird's mChannel and mObserverList
objects. An attacker could exploit these to possibly run
arbitrary code as the user running Thunderbird.
(CVE-2011-0065, CVE-2011-0066)

It was discovered that there was a vulnerability in the
handling of the nsTreeSelection element. An attacker sending
a specially crafted E-Mail could exploit this to possibly
run arbitrary code as the user running Thunderbird.
(CVE-2011-0073)

Paul Stone discovered a vulnerability in the handling of
Java applets. If plugins were enabled, an attacker could use
this to mimic interaction with form autocomplete controls
and steal entries from the form history. (CVE-2011-0067)

Soroush Dalili discovered a vulnerability in the resource:
protocol. This could potentially allow an attacker to load
arbitrary files that were accessible to the user running
Thunderbird. (CVE-2011-0071)

Chris Evans discovered a vulnerability in Thunderbird's XSLT
generate-id() function. An attacker could possibly use this
vulnerability to make other attacks more reliable.
(CVE-2011-1202).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"thunderbird", pkgver:"3.1.10+build1+nobinonly-0ubuntu0.11.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
