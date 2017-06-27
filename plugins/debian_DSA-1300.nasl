#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1300. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25463);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2870", "CVE-2007-2871");
  script_osvdb_id(35139);
  script_xref(name:"DSA", value:"1300");

  script_name(english:"Debian DSA-1300-1 : iceape - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Iceape
internet suite, an unbranded version of the SeaMonkey Internet Suite.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2007-1362
    Nicolas Derouet discovered that Iceape performs
    insufficient validation of cookies, which could lead to
    denial of service.

  - CVE-2007-1558
    Gatan Leurent discovered a cryptographical weakness in
    APOP authentication, which reduces the required efforts
    for an MITM attack to intercept a password. The update
    enforces stricter validation, which prevents this
    attack.

  - CVE-2007-2867
    Boris Zbarsky, Eli Friedman, Georgi Guninski, Jesse
    Ruderman, Martijn Wargers and Olli Pettay discovered
    crashes in the layout engine, which might allow the
    execution of arbitrary code.

  - CVE-2007-2868
    Brendan Eich, Igor Bukanov, Jesse Ruderman,
    'moz_bug_r_a4' and Wladimir Palant discovered crashes in
    the JavaScript engine, which might allow the execution
    of arbitrary code.

  - CVE-2007-2870
    'moz_bug_r_a4' discovered that adding an event listener
    through the addEventListener() function allows
    cross-site scripting.

  - CVE-2007-2871
    Chris Thomas discovered that XUL popups can be abused
    for spoofing or phishing attacks.

Fixes for the oldstable distribution (sarge) are not available. While
there will be another round of security updates for Mozilla products,
Debian doesn't have the resources to backport further security fixes
to the old Mozilla products. You're strongly encouraged to upgrade to
stable as soon as possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1300"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (etch) these problems have been fixed in
version 1.0.9-0etch1. A build for the arm architecture is not yet
available, it will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/30");
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
if (deb_check(release:"4.0", prefix:"iceape", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-browser", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-calendar", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-chatzilla", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dbg", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dev", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dom-inspector", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-gnome-support", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-mailnews", reference:"1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-browser", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-calendar", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-chatzilla", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-dev", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-dom-inspector", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-js-debugger", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-mailnews", reference:"1.8+1.0.9-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-psm", reference:"1.8+1.0.9-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
