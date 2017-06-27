#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1306. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25505);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_osvdb_id(35139);
  script_xref(name:"DSA", value:"1306");

  script_name(english:"Debian DSA-1306-1 : xulrunner - several vulnerabilities");
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

  - CVE-2007-1362
    Nicolas Derouet discovered that Xulrunner performs
    insufficient validation of cookies, which could lead to
    denial of service.

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

  - CVE-2007-2869
    'Marcel' discovered that malicious websites can cause
    massive resource consumption through the auto completion
    feature, resulting in denial of service.

  - CVE-2007-2870
    'moz_bug_r_a4' discovered that adding an event listener
    through theaddEventListener() function allows cross-site
    scripting.

  - CVE-2007-2871
    Chris Thomas discovered that XUL popups can be abused
    for spoofing or phishing attacks.

The oldstable distribution (sarge) doesn't include xulrunner."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1362"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2869"
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
    value:"http://www.debian.org/security/2007/dsa-1306"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (etch) these problems have been fixed in
version 1.8.0.12-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
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
if (deb_check(release:"4.0", prefix:"libmozillainterfaces-java", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs-dev", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d-dbg", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d-dbg", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-dev", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d-dbg", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-dev", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-tools", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs-dev", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs1", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-common", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-dev", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d-dbg", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-xpcom", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"spidermonkey-bin", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner", reference:"1.8.0.12-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner-gnome-support", reference:"1.8.0.12-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
