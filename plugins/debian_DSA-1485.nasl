#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1485. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30225);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_bugtraq_id(27406, 27683);
  script_osvdb_id(42056, 43226);
  script_xref(name:"DSA", value:"1485");

  script_name(english:"Debian DSA-1485-2 : icedove - several vulnerabilities");
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

  - CVE-2008-0412
    Jesse Ruderman, Kai Engert, Martijn Wargers, Mats
    Palmgren and Paul Nickerson discovered crashes in the
    layout engine, which might allow the execution of
    arbitrary code.

  - CVE-2008-0413
    Carsten Book, Wesley Garland, Igor Bukanov,
    'moz_bug_r_a4', 'shutdown', Philip Taylor and 'tgirmann'
    discovered crashes in the JavaScript engine, which might
    allow the execution of arbitrary code.

  - CVE-2008-0415
    'moz_bug_r_a4' and Boris Zbarsky discovered several
    vulnerabilities in JavaScript handling, which could
    allow privilege escalation.

  - CVE-2008-0418
    Gerry Eisenhaur and 'moz_bug_r_a4' discovered that a
    directory traversal vulnerability in chrome: URI
    handling could lead to information disclosure.

  - CVE-2008-0419
    David Bloom discovered a race condition in the image
    handling of designMode elements, which can lead to
    information disclosure and potentially the execution of
    arbitrary code.

  - CVE-2008-0591
    Michal Zalewski discovered that timers protecting
    security-sensitive dialogs (by disabling dialog elements
    until a timeout is reached) could be bypassed by window
    focus changes through JavaScript.

The Mozilla products from the old stable distribution (sarge) are no
longer supported with security updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1485"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (etch), these problems have been fixed in
version 1.5.0.13+1.5.0.15b.dfsg1-0etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 79, 94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
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
if (deb_check(release:"4.0", prefix:"icedove", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dbg", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dev", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-gnome-support", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-inspector", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird", reference:"1.5.0.13+1.5.0.15a.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-dev", reference:"1.5.0.13+1.5.0.15a.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-inspector", reference:"1.5.0.13+1.5.0.15a.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dbg", reference:"1.5.0.13+1.5.0.15a.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dev", reference:"1.5.0.13+1.5.0.15a.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-gnome-support", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-inspector", reference:"1.5.0.13+1.5.0.15a.dfsg1-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1-0etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
