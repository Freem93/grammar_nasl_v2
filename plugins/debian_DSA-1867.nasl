#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1867. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44732);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
  script_bugtraq_id(35271, 35309, 35318);
  script_xref(name:"DSA", value:"1867");

  script_name(english:"Debian DSA-1867-1 : kdelibs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been discovered in kdelibs, core
libraries from the official KDE release. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2009-1690
    It was discovered that there is a use-after-free flaw in
    handling certain DOM event handlers. This could lead to
    the execution of arbitrary code, when visiting a
    malicious website.

  - CVE-2009-1698
    It was discovered that there could be an uninitialised
    pointer when handling a Cascading Style Sheets (CSS)
    attr function call. This could lead to the execution of
    arbitrary code, when visiting a malicious website.

  - CVE-2009-1687
    It was discovered that the JavaScript garbage collector
    does not handle allocation failures properly, which
    could lead to the execution of arbitrary code when
    visiting a malicious website."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1867"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdelibs packages.

For the oldstable distribution (etch), these problems have been fixed
in version 4:3.5.5a.dfsg.1-8etch2.

For the stable distribution (lenny), these problems have been fixed in
version 4:3.5.10.dfsg.1-0lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/19");
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
if (deb_check(release:"4.0", prefix:"kdelibs", reference:"4:3.5.5a.dfsg.1-8etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs-data", reference:"4:3.5.5a.dfsg.1-8etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs-dbg", reference:"4:3.5.5a.dfsg.1-8etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs4-dev", reference:"4:3.5.5a.dfsg.1-8etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs4-doc", reference:"4:3.5.5a.dfsg.1-8etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs4c2a", reference:"4:3.5.5a.dfsg.1-8etch2")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs", reference:"4:3.5.10.dfsg.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs-data", reference:"4:3.5.10.dfsg.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs-dbg", reference:"4:3.5.10.dfsg.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs4-dev", reference:"4:3.5.10.dfsg.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs4-doc", reference:"4:3.5.10.dfsg.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs4c2a", reference:"4:3.5.10.dfsg.1-0lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
