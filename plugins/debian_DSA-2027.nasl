#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2027. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45412);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179");
  script_bugtraq_id(39124);
  script_osvdb_id(63637);
  script_xref(name:"DSA", value:"2027");

  script_name(english:"Debian DSA-2027-1 : xulrunner - several vulnerabilities");
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

  - CVE-2010-0174
    Jesse Ruderman and Ehsan Akhgari discovered crashes in
    the layout engine, which might allow the execution of
    arbitrary code.

  - CVE-2010-0175
    It was discovered that incorrect memory handling in the
    XUL event handler might allow the execution of arbitrary
    code.

  - CVE-2010-0176
    It was discovered that incorrect memory handling in the
    XUL event handler might allow the execution of arbitrary
    code.

  - CVE-2010-0177
    It was discovered that incorrect memory handling in the
    plugin code might allow the execution of arbitrary code.

  - CVE-2010-0178
    Paul Stone discovered that forced drag-and-drop events
    could lead to Chrome privilege escalation.

  - CVE-2010-0179
    It was discovered that a programming error in the
    XMLHttpRequestSpy module could lead to the execution of
    arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2027"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/05");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.19-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.19-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
