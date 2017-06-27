#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1345. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25853);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-3844", "CVE-2007-3845");
  script_osvdb_id(38026, 38031);
  script_xref(name:"DSA", value:"1345");

  script_name(english:"Debian DSA-1345-1 : xulrunner - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities
and Exposures project identifies the following problems :

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

The oldstable distribution (sarge) doesn't include xulrunner."
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
    value:"http://www.debian.org/security/2007/dsa-1345"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (etch) these problems have been fixed in
version 1.8.0.13~pre070720-0etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/30");
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
if (deb_check(release:"4.0", prefix:"libmozillainterfaces-java", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs-dev", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d-dbg", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d-dbg", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-dev", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d-dbg", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-dev", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-tools", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs-dev", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs1", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-common", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-dev", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d-dbg", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"python-xpcom", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"spidermonkey-bin", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner", reference:"1.8.0.13~pre070720-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner-gnome-support", reference:"1.8.0.13~pre070720-0etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
