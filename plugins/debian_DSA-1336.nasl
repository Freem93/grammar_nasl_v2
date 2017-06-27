#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1336. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25779);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0045", "CVE-2007-0775", "CVE-2007-0778", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1282");
  script_osvdb_id(32103, 32104, 32105, 32106, 32107, 32108, 32109, 32110, 32111, 32112, 32113, 32114, 32115, 33812);
  script_xref(name:"DSA", value:"1336");

  script_name(english:"Debian DSA-1336-1 : mozilla-firefox - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Mozilla
Firefox.

This will be the last security update of Mozilla-based products for
the oldstable (sarge) distribution of Debian. We recommend to upgrade
to stable (etch) as soon as possible.

The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities :

  - CVE-2007-1282
    It was discovered that an integer overflow in
    text/enhanced message parsing allows the execution of
    arbitrary code.

  - CVE-2007-0994
    It was discovered that a regression in the JavaScript
    engine allows the execution of JavaScript with elevated
    privileges.

  - CVE-2007-0995
    It was discovered that incorrect parsing of invalid HTML
    characters allows the bypass of content filters.

  - CVE-2007-0996
    It was discovered that insecure child frame handling
    allows cross-site scripting.

  - CVE-2007-0981
    It was discovered that Firefox handles URI with a null
    byte in the hostname insecurely.

  - CVE-2007-0008
    It was discovered that a buffer overflow in the NSS code
    allows the execution of arbitrary code.

  - CVE-2007-0009
    It was discovered that a buffer overflow in the NSS code
    allows the execution of arbitrary code.

  - CVE-2007-0775
    It was discovered that multiple programming errors in
    the layout engine allow the execution of arbitrary code.

  - CVE-2007-0778
    It was discovered that the page cache calculates hashes
    in an insecure manner.

  - CVE-2006-6077
    It was discovered that the password manager allows the
    disclosure of passwords."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1336"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the oldstable distribution (sarge) these problems have been fixed
in version 1.0.4-2sarge17. You should upgrade to etch as soon as
possible.

The stable distribution (etch) isn't affected. These vulnerabilities
have been fixed prior to the release of Debian etch."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mozilla-firefox", reference:"1.0.4-2sarge17")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-dom-inspector", reference:"1.0.4-2sarge17")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-gnome-support", reference:"1.0.4-2sarge17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
