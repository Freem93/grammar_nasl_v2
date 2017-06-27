#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1956. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44821);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2009-3979", "CVE-2009-3981", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");
  script_bugtraq_id(37361, 37363, 37365, 37366, 37367, 37370);
  script_osvdb_id(61094, 61095, 61096, 61099, 61100, 61101);
  script_xref(name:"DSA", value:"1956");

  script_name(english:"Debian DSA-1956-1 : xulrunner - several vulnerabilities");
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

  - CVE-2009-3986 :
    David James discovered that the window.opener property
    allows Chrome privilege escalation.

  - CVE-2009-3985 :
    Jordi Chanel discovered a spoofing vulnerability of the
    URL location bar using the document.location property.

  - CVE-2009-3984 :
    Jonathan Morgan discovered that the icon indicating a
    secure connection could be spoofed through the
    document.location property.

  - CVE-2009-3983 :
    Takehiro Takahashi discovered that the NTLM
    implementation is vulnerable to reflection attacks.

  - CVE-2009-3981 :
    Jesse Ruderman discovered a crash in the layout engine,
    which might allow the execution of arbitrary code.

  - CVE-2009-3979 :
    Jesse Ruderman, Josh Soref, Martijn Wargers, Jose Angel
    and Olli Pettay discovered crashes in the layout engine,
    which might allow the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1956"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.16-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.16-1")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.16-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
