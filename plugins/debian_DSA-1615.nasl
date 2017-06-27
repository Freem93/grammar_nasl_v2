#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1615. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33567);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2811", "CVE-2008-2933");
  script_osvdb_id(47465);
  script_xref(name:"DSA", value:"1615");

  script_name(english:"Debian DSA-1615-1 : xulrunner - several vulnerabilities");
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

  - CVE-2008-2785
    It was discovered that missing boundary checks on a
    reference counter for CSS objects can lead to the
    execution of arbitrary code.

  - CVE-2008-2798
    Devon Hubbard, Jesse Ruderman and Martijn Wargers
    discovered crashes in the layout engine, which might
    allow the execution of arbitrary code.

  - CVE-2008-2799
    Igor Bukanov, Jesse Ruderman and Gary Kwong discovered
    crashes in the JavaScript engine, which might allow the
    execution of arbitrary code.

  - CVE-2008-2800
    'moz_bug_r_a4' discovered several cross-site scripting
    vulnerabilities.

  - CVE-2008-2801
    Collin Jackson and Adam Barth discovered that JavaScript
    code could be executed in the context of signed JAR
    archives.

  - CVE-2008-2802
    'moz_bug_r_a4' discovered that XUL documents can
    escalate privileges by accessing the pre-compiled
    'fastload' file.

  - CVE-2008-2803
    'moz_bug_r_a4' discovered that missing input sanitising
    in the mozIJSSubScriptLoader.loadSubScript() function
    could lead to the execution of arbitrary code. Iceweasel
    itself is not affected, but some addons are.

  - CVE-2008-2805
    Claudio Santambrogio discovered that missing access
    validation in DOM parsing allows malicious websites to
    force the browser to upload local files to the server,
    which could lead to information disclosure.

  - CVE-2008-2807
    Daniel Glazman discovered that a programming error in
    the code for parsing .properties files could lead to
    memory content being exposed to addons, which could lead
    to information disclosure.

  - CVE-2008-2808
    Masahiro Yamada discovered that file URLs in directory
    listings were insufficiently escaped.

  - CVE-2008-2809
    John G. Myers, Frank Benkstein and Nils Toedtmann
    discovered that alternate names on self-signed
    certificates were handled insufficiently, which could
    lead to spoofing of secure connections.

  - CVE-2008-2811
    Greg McManus discovered a crash in the block reflow
    code, which might allow the execution of arbitrary code.

  - CVE-2008-2933
    Billy Rios discovered that passing an URL containing a
    pipe symbol to Iceweasel can lead to Chrome privilege
    escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1615"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (etch), these problems have been fixed in
version 1.8.0.15~pre080614d-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 189, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/24");
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
if (deb_check(release:"4.0", prefix:"libmozillainterfaces-java", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs-dev", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d-dbg", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d-dbg", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-dev", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d-dbg", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-dev", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-tools", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs-dev", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs1", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-common", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-dev", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d-dbg", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-xpcom", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"spidermonkey-bin", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner", reference:"1.8.0.15~pre080614d-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner-gnome-support", reference:"1.8.0.15~pre080614d-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
