#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1535. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31806);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-4879", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
  script_bugtraq_id(28448);
  script_xref(name:"DSA", value:"1535");

  script_name(english:"Debian DSA-1535-1 : iceweasel - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# This shares a lot of text with dsa-1532.wml, dsa-1534.wml,
dsa-1574.wml

Several remote vulnerabilities have been discovered in the Iceweasel
web browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-4879
    Peter Brodersen and Alexander Klink discovered that the
    autoselection of SSL client certificates could lead to
    users being tracked, resulting in a loss of privacy.

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
    execution of arbitrary code.

  - CVE-2008-1238
    Gregory Fleischer discovered that HTTP Referrer headers
    were handled incorrectly in combination with URLs
    containing Basic Authentication credentials with empty
    usernames, resulting in potential Cross-Site Request
    Forgery attacks.

  - CVE-2008-1240
    Gregory Fleischer discovered that web content fetched
    through the jar: protocol can use Java to connect to
    arbitrary ports. This is only an issue in combination
    with the non-free Java plugin.

  - CVE-2008-1241
    Chris Thomas discovered that background tabs could
    generate XUL popups overlaying the current tab,
    resulting in potential spoofing attacks.

The Mozilla products from the old stable distribution (sarge) are no
longer supported."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4879"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1535"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (etch), these problems have been fixed in
version 2.0.0.13-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");
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
if (deb_check(release:"4.0", prefix:"firefox", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-dom-inspector", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-gnome-support", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dbg", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dom-inspector", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-gnome-support", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-dom-inspector", reference:"2.0.0.13-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-gnome-support", reference:"2.0.0.13-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
