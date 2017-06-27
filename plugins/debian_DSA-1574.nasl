#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1574. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32308);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237");
  script_bugtraq_id(28448);
  script_xref(name:"DSA", value:"1574");

  script_name(english:"Debian DSA-1574-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# This shares a lot of text with dsa-1532.wml, dsa-1534.wml,
dsa-1535.wml

Several remote vulnerabilities have been discovered in the Icedove
mail client, an unbranded version of the Thunderbird client. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-1233
    'moz_bug_r_a4' discovered that variants of CVE-2007-3738
    and CVE-2007-5338 allow the execution of arbitrary code
    through XPCNativeWrapper.

  - CVE-2008-1234
    'moz_bug_r_a4' discovered that insecure handling of
    event handlers could lead to cross-site scripting.

  - CVE-2008-1235
    Boris Zbarsky, Johnny Stenback and 'moz_bug_r_a4'
    discovered that incorrect principal handling could lead
    to cross-site scripting and the execution of arbitrary
    code.

  - CVE-2008-1236
    Tom Ferris, Seth Spitzer, Martin Wargers, John Daggett
    and Mats Palmgren discovered crashes in the layout
    engine, which might allow the execution of arbitrary
    code.

  - CVE-2008-1237
    'georgi', 'tgirmann' and Igor Bukanov discovered crashes
    in the JavaScript engine, which might allow the
    execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1574"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (etch), these problems have been fixed in
version 1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/13");
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
if (deb_check(release:"4.0", prefix:"icedove", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dbg", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dev", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-gnome-support", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-inspector", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-dev", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-inspector", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dbg", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dev", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-gnome-support", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-inspector", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
