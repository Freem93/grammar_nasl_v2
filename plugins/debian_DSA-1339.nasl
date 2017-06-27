#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1339. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25801);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/08/21 14:15:32 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_osvdb_id(38000, 38001, 38002, 38010, 38015, 38016, 38024, 38028);
  script_xref(name:"DSA", value:"1339");

  script_name(english:"Debian DSA-1339-1 : iceape - several vulnerabilities");
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

  - CVE-2007-3089
    Ronen Zilberman and Michal Zalewski discovered that a
    timing race allows the injection of content into
    about:blank frames.

  - CVE-2007-3656
    Michal Zalewski discovered that same-origin policies for
    wyciwyg:// documents are insufficiently enforced.

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

  - CVE-2007-3736
    'moz_bug_r_a4' discovered that the addEventListener()
    and setTimeout() functions allow cross-site scripting.

  - CVE-2007-3737
    'moz_bug_r_a4' discovered that a programming error in
    event handling allows privilege escalation.

  - CVE-2007-3738
    'shutdown' and 'moz_bug_r_a4' discovered that the
    XPCNativeWrapper allows the execution of arbitrary code.

The Mozilla products in the oldstable distribution (sarge) are no
longer supported with security updates. You're strongly encouraged to
upgrade to stable as soon as possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3656"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1339"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (etch) these problems have been fixed in
version 1.0.10~pre070720-0etch1. A build for the mips architecture is
not yet available, it will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/04");
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
if (deb_check(release:"4.0", prefix:"iceape", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-browser", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-calendar", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-chatzilla", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dbg", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dev", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dom-inspector", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-gnome-support", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-mailnews", reference:"1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-browser", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-calendar", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-chatzilla", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-dev", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-dom-inspector", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-js-debugger", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-mailnews", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-psm", reference:"1.8+1.0.10~pre070720-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
