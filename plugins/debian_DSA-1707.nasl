#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1707. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35384);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_bugtraq_id(32882);
  script_xref(name:"DSA", value:"1707");

  script_name(english:"Debian DSA-1707-1 : iceweasel - several vulnerabilities");
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

  - CVE-2008-5500
    Jesse Ruderman discovered that the layout engine is
    vulnerable to DoS attacks that might trigger memory
    corruption and an integer overflow. (MFSA 2008-60)

  - CVE-2008-5503
    Boris Zbarsky discovered that an information disclosure
    attack could be performed via XBL bindings. (MFSA
    2008-61)

  - CVE-2008-5504
    It was discovered that attackers could run arbitrary
    JavaScript with chrome privileges via vectors related to
    the feed preview. (MFSA 2008-62)

  - CVE-2008-5506
    Marius Schilder discovered that it is possible to obtain
    sensible data via a XMLHttpRequest. (MFSA 2008-64)

  - CVE-2008-5507
    Chris Evans discovered that it is possible to obtain
    sensible data via a JavaScript URL. (MFSA 2008-65)

  - CVE-2008-5508
    Chip Salzenberg discovered possible phishing attacks via
    URLs with leading whitespaces or control characters.
    (MFSA 2008-66)

  - CVE-2008-5510
    Kojima Hajime and Jun Muto discovered that escaped null
    characters were ignored by the CSS parser and could lead
    to the bypass of protection mechanisms (MFSA 2008-67)

  - CVE-2008-5511
    It was discovered that it is possible to perform
    cross-site scripting attacks via an XBL binding to an
    'unloaded document.' (MFSA 2008-68)

  - CVE-2008-5512
    It was discovered that it is possible to run arbitrary
    JavaScript with chrome privileges via unknown vectors.
    (MFSA 2008-68)

  - CVE-2008-5513
    moz_bug_r_a4 discovered that the session-restore feature
    does not properly sanitise input leading to arbitrary
    injections. This issue could be used to perform an XSS
    attack or run arbitrary JavaScript with chrome
    privileges. (MFSA 2008-69)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1707"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel package.

For the stable distribution (etch) these problems have been fixed in
version 2.0.0.19-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"firefox", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-dom-inspector", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-gnome-support", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dbg", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dom-inspector", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-gnome-support", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-dom-inspector", reference:"2.0.0.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-gnome-support", reference:"2.0.0.19-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
