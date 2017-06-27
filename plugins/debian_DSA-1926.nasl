#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1926. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44791);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-3628", "CVE-2009-3629", "CVE-2009-3630", "CVE-2009-3631", "CVE-2009-3632", "CVE-2009-3633", "CVE-2009-3634", "CVE-2009-3635", "CVE-2009-3636");
  script_osvdb_id(59483, 59484, 59485, 59486, 59487, 59488, 59489, 59490, 59491);
  script_xref(name:"DSA", value:"1926");

  script_name(english:"Debian DSA-1926-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-3628
    The Backend subcomponent allows remote authenticated
    users to determine an encryption key via crafted input
    to a form field.

  - CVE-2009-3629
    Multiple cross-site scripting (XSS) vulnerabilities in
    the Backend subcomponent allow remote authenticated
    users to inject arbitrary web script or HTML.

  - CVE-2009-3630
    The Backend subcomponent allows remote authenticated
    users to place arbitrary websites in TYPO3 backend
    framesets via crafted parameters.

  - CVE-2009-3631
    The Backend subcomponent, when the DAM extension or ftp
    upload is enabled, allows remote authenticated users to
    execute arbitrary commands via shell metacharacters in a
    filename.

  - CVE-2009-3632
    SQL injection vulnerability in the traditional frontend
    editing feature in the Frontend Editing subcomponent
    allows remote authenticated users to execute arbitrary
    SQL commands.

  - CVE-2009-3633
    Cross-site scripting (XSS) vulnerability allows remote
    attackers to inject arbitrary web script.

  - CVE-2009-3634
    Cross-site scripting (XSS) vulnerability in the Frontend
    Login Box (aka felogin) subcomponent allows remote
    attackers to inject arbitrary web script or HTML.

  - CVE-2009-3635
    The Install Tool subcomponent allows remote attackers to
    gain access by using only the password's md5 hash as a
    credential.

  - CVE-2009-3636
    Cross-site scripting (XSS) vulnerability in the Install
    Tool subcomponent allows remote attackers to inject
    arbitrary web script or HTML."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=552020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1926"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the typo3-src package.

For the old stable distribution (etch), these problems have been fixed
in version 4.0.2+debian-9.

For the stable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(79, 89, 94, 200, 287, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"typo3", reference:"4.0.2+debian-9")) flag++;
if (deb_check(release:"4.0", prefix:"typo3-src-4.0", reference:"4.0.2+debian-9")) flag++;
if (deb_check(release:"5.0", prefix:"typo3", reference:"4.2.5-1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"typo3-src-4.2", reference:"4.2.5-1+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
