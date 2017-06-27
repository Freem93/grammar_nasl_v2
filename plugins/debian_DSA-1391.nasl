#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1391. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27546);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/22 11:11:53 $");

  script_cve_id("CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3844", "CVE-2007-3845", "CVE-2007-5339", "CVE-2007-5340");
  script_xref(name:"DSA", value:"1391");

  script_name(english:"Debian DSA-1391-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Icedove
mail client, an unbranded version of the Thunderbird client. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-3734
    Bernd Mielke, Boris Zbarsky, David Baron, Daniel Veditz,
    Jesse Ruderman, Lukas Loehrer, Martijn Wargers, Mats
    Palmgren, Olli Pettay, Paul Nickerson and Vladimir
    Sukhoy discovered crashes in the layout engine, which
    might allow the execution of arbitrary code.

  - CVE-2007-3735
    Asaf Romano, Jesse Ruderman and Igor Bukanov discovered
    crashes in the JavaScript engine, which might allow the
    execution of arbitrary code.

  - CVE-2007-3844
    'moz_bug_r_a4' discovered that a regression in the
    handling of'about:blank' windows used by addons may lead
    to an attacker being able to modify the content of
    websites.

  - CVE-2007-3845
    Jesper Johansson discovered that missing sanitising of
    double-quotes and spaces in URIs passed to external
    programs may allow an attacker to pass arbitrary
    arguments to the helper program if the user is tricked
    into opening a malformed web page.

  - CVE-2007-5339
    L. David Baron, Boris Zbarsky, Georgi Guninski, Paul
    Nickerson, Olli Pettay, Jesse Ruderman, Vladimir Sukhoy,
    Daniel Veditz, and Martijn Wargers discovered crashes in
    the layout engine, which might allow the execution of
    arbitrary code.

  - CVE-2007-5340
    Igor Bukanov, Eli Friedman, and Jesse Ruderman
    discovered crashes in the JavaScript engine, which might
    allow the execution of arbitrary code. Generally,
    enabling JavaScript in Icedove is not recommended.

The Mozilla products in the oldstable distribution (sarge) are no
longer supported with security updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1391"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (etch) these problems have been fixed in
version 1.5.0.13+1.5.0.14b.dfsg1-0etch1. Builds for hppa will be
provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"icedove", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dbg", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dev", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-gnome-support", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-inspector", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-typeaheadfind", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-dev", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-inspector", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dbg", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dev", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-gnome-support", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-inspector", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.14b.dfsg1-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
