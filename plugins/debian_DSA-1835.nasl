#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1835. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44700);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-2285", "CVE-2009-2347");
  script_bugtraq_id(35451, 35652);
  script_xref(name:"DSA", value:"1835");

  script_name(english:"Debian DSA-1835-1 : tiff - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the library for the
Tag Image File Format (TIFF). The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-2285
    It was discovered that malformed TIFF images can lead to
    a crash in the decompression code, resulting in denial
    of service.

  - CVE-2009-2347
    Andrea Barisani discovered several integer overflows,
    which can lead to the execution of arbitrary code if
    malformed images are passed to the rgb2ycbcr or
    tiff2rgba tools."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1835"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tiff packages.

For the old stable distribution (etch), these problems have been fixed
in version 3.8.2-7+etch3.

For the stable distribution (lenny), these problems have been fixed in
version 3.8.2-11.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/15");
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
if (deb_check(release:"4.0", prefix:"libtiff-opengl", reference:"3.8.2-7+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libtiff-tools", reference:"3.8.2-7+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libtiff4", reference:"3.8.2-7+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libtiff4-dev", reference:"3.8.2-7+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libtiffxx0c2", reference:"3.8.2-7+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"libtiff-doc", reference:"3.8.2-11.2")) flag++;
if (deb_check(release:"5.0", prefix:"libtiff-opengl", reference:"3.8.2-11.2")) flag++;
if (deb_check(release:"5.0", prefix:"libtiff-tools", reference:"3.8.2-11.2")) flag++;
if (deb_check(release:"5.0", prefix:"libtiff4", reference:"3.8.2-11.2")) flag++;
if (deb_check(release:"5.0", prefix:"libtiff4-dev", reference:"3.8.2-11.2")) flag++;
if (deb_check(release:"5.0", prefix:"libtiffxx0c2", reference:"3.8.2-11.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
