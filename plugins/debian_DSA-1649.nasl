#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1649. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34371);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069");
  script_xref(name:"DSA", value:"1649");

  script_name(english:"Debian DSA-1649-1 : iceweasel - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Iceweasel
web browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-0016
    Justin Schuh, Tom Cross and Peter Williams discovered a
    buffer overflow in the parser for UTF-8 URLs, which may
    lead to the execution of arbitrary code.

  - CVE-2008-3835
    'moz_bug_r_a4' discovered that the same-origin check in
    nsXMLDocument::OnChannelRedirect() could by bypassed.

  - CVE-2008-3836
    'moz_bug_r_a4' discovered that several vulnerabilities
    in feedWriter could lead to Chrome privilege escalation.

  - CVE-2008-3837
    Paul Nickerson discovered that an attacker could move
    windows during a mouse click, resulting in unwanted
    action triggered by drag-and-drop.

  - CVE-2008-4058
    'moz_bug_r_a4' discovered a vulnerability which can
    result in Chrome privilege escalation through
    XPCNativeWrappers.

  - CVE-2008-4059
    'moz_bug_r_a4' discovered a vulnerability which can
    result in Chrome privilege escalation through
    XPCNativeWrappers.

  - CVE-2008-4060
    Olli Pettay and 'moz_bug_r_a4' discovered a Chrome
    privilege escalation vulnerability in XSLT handling.

  - CVE-2008-4061
    Jesse Ruderman discovered a crash in the layout engine,
    which might allow the execution of arbitrary code.

  - CVE-2008-4062
    Igor Bukanov, Philip Taylor, Georgi Guninski and Antoine
    Labour discovered crashes in the JavaScript engine,
    which might allow the execution of arbitrary code.

  - CVE-2008-4065
    Dave Reed discovered that some Unicode byte order marks
    are stripped from JavaScript code before execution,
    which can result in code being executed, which were
    otherwise part of a quoted string.

  - CVE-2008-4066
    Gareth Heyes discovered that some Unicode surrogate
    characters are ignored by the HTML parser.

  - CVE-2008-4067
    Boris Zbarsky discovered that resource: URLs allow
    directory traversal when using URL-encoded slashes.

  - CVE-2008-4068
    Georgi Guninski discovered that resource: URLs could
    bypass local access restrictions.

  - CVE-2008-4069
    Billy Hoffman discovered that the XBM decoder could
    reveal uninitialised memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1649"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (etch), these problems have been fixed in
version 2.0.0.17-0etch1. Packages for hppa will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 79, 119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"4.0", prefix:"firefox", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-dom-inspector", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-gnome-support", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dbg", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dom-inspector", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-gnome-support", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-dom-inspector", reference:"2.0.0.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-gnome-support", reference:"2.0.0.17-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
