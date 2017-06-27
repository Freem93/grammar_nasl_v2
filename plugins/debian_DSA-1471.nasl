#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1471. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30063);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4066");
  script_xref(name:"DSA", value:"1471");

  script_name(english:"Debian DSA-1471-1 : libvorbis - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in the Vorbis General Audio
Compression Codec, which may lead to denial of service or the
execution of arbitrary code, if a user is tricked into opening a
malformed Ogg Audio file with an application linked against libvorbis."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1471"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvorbis packages.

For the old stable distribution (sarge), these problems have been
fixed in version 1.1.0-2.

For the stable distribution (etch), these problems have been fixed in
version 1.1.2.dfsg-1.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/21");
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
if (deb_check(release:"3.1", prefix:"libvorbis-dev", reference:"1.1.0-2")) flag++;
if (deb_check(release:"3.1", prefix:"libvorbis0a", reference:"1.1.0-2")) flag++;
if (deb_check(release:"3.1", prefix:"libvorbisenc2", reference:"1.1.0-2")) flag++;
if (deb_check(release:"3.1", prefix:"libvorbisfile3", reference:"1.1.0-2")) flag++;
if (deb_check(release:"4.0", prefix:"libvorbis-dev", reference:"1.1.2.dfsg-1.3")) flag++;
if (deb_check(release:"4.0", prefix:"libvorbis0a", reference:"1.1.2.dfsg-1.3")) flag++;
if (deb_check(release:"4.0", prefix:"libvorbisenc2", reference:"1.1.2.dfsg-1.3")) flag++;
if (deb_check(release:"4.0", prefix:"libvorbisfile3", reference:"1.1.2.dfsg-1.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
