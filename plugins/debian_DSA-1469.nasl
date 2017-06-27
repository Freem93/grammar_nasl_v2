#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1469. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30061);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-4619", "CVE-2007-6277");
  script_osvdb_id(41694, 44954);
  script_xref(name:"DSA", value:"1469");

  script_name(english:"Debian DSA-1469-1 : flac - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sean de Regge and Greg Linares discovered multiple heap and stack
based buffer overflows in FLAC, the Free Lossless Audio Codec, which
could lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1469"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the flac packages.

For the old stable distribution (sarge), these problems have been
fixed in version 1.1.1-5sarge1.

For the stable distribution (etch), these problems have been fixed in
version 1.1.2-8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:flac");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/27");
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
if (deb_check(release:"3.1", prefix:"flac", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libflac++-dev", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libflac++4", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libflac-dev", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libflac6", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"liboggflac++-dev", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"liboggflac++0c102", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"liboggflac-dev", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"liboggflac1", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"xmms-flac", reference:"1.1.1-5sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"flac", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"libflac++-dev", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"libflac++5", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"libflac-dev", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"libflac-doc", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"libflac7", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"liboggflac++-dev", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"liboggflac++2", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"liboggflac-dev", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"liboggflac3", reference:"1.1.2-8")) flag++;
if (deb_check(release:"4.0", prefix:"xmms-flac", reference:"1.1.2-8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
