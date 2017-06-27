#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2075. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47889);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2010-0182", "CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1208", "CVE-2010-1211", "CVE-2010-1214", "CVE-2010-2751", "CVE-2010-2753", "CVE-2010-2754");
  script_bugtraq_id(39479, 41174, 41842, 41849, 41853, 41859, 41860, 41872, 41968);
  script_osvdb_id(62464, 63620, 65852, 66590, 66593, 66594, 66595, 66596, 66600, 66601, 66605);
  script_xref(name:"DSA", value:"2075");

  script_name(english:"Debian DSA-2075-1 : xulrunner - several vulnerabilities");
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

  - CVE-2010-0182
    Wladimir Palant discovered that security checks in XML
    processing were insufficiently enforced.

  - CVE-2010-0654
    Chris Evans discovered that insecure CSS handling could
    lead to reading data across domain boundaries.

  - CVE-2010-1205
    Aki Helin discovered a buffer overflow in the internal
    copy of libpng, which could lead to the execution of
    arbitrary code.

  - CVE-2010-1208
    'regenrecht' discovered that incorrect memory handling
    in DOM parsing could lead to the execution of arbitrary
    code.

  - CVE-2010-1211
    Jesse Ruderman, Ehsan Akhgari, Mats Palmgren, Igor
    Bukanov, Gary Kwong, Tobias Markus and Daniel Holbert
    discovered crashes in the layout engine, which might
    allow the execution of arbitrary code.

  - CVE-2010-1214
    'JS3' discovered an integer overflow in the plugin code,
    which could lead to the execution of arbitrary code.

  - CVE-2010-2751
    Jordi Chancel discovered that the location could be
    spoofed to appear like a secured page.

  - CVE-2010-2753
    'regenrecht' discovered that incorrect memory handling
    in XUL parsing could lead to the execution of arbitrary
    code.

  - CVE-2010-2754
    Soroush Dalili discovered an information leak in script
    processing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2075"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.19-3")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.19-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
