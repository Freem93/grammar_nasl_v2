#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1922. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44787);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3382");
  script_bugtraq_id(36852, 36853, 36855);
  script_osvdb_id(57844, 59381, 59384, 59389, 59390, 59391, 59392, 59393, 59394);
  script_xref(name:"DSA", value:"1922");

  script_name(english:"Debian DSA-1922-1 : xulrunner - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2009-3380
    Vladimir Vukicevic, Jesse Ruderman, Martijn Wargers,
    Daniel Banchero, David Keeler and Boris Zbarsky reported
    crashes in layout engine, which might allow the
    execution of arbitrary code.

  - CVE-2009-3382
    Carsten Book reported a crash in the layout engine,
    which might allow the execution of arbitrary code.

  - CVE-2009-3376
    Jesse Ruderman and Sid Stamm discovered spoofing
    vulnerability in the file download dialog.

  - CVE-2009-3375
    Gregory Fleischer discovered a bypass of the same-origin
    policy using the document.getSelection() function.

  - CVE-2009-3374
    'moz_bug_r_a4' discovered a privilege escalation to
    Chrome status in the XPCOM utility
    XPCVariant::VariantDataToJS.

  - CVE-2009-3373
    'regenrecht' discovered a buffer overflow in the GIF
    parser, which might lead to the execution of arbitrary
    code.

  - CVE-2009-3372
    Marco C. discovered that a programming error in the
    proxy auto configuration code might lead to denial of
    service or the execution of arbitrary code.

  - CVE-2009-3274
    Jeremy Brown discovered that the filename of a
    downloaded file which is opened by the user is
    predictable, which might lead to tricking the user into
    a malicious file if the attacker has local access to the
    system.

  - CVE-2009-3370
    Paul Stone discovered that history information from web
    forms could be stolen."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1922"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.15-0lenny1.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/28");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.15-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.15-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
