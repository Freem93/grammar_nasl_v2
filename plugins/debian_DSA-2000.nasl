#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2000. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44864);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-4631", "CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4636", "CVE-2009-4637", "CVE-2009-4638", "CVE-2009-4640");
  script_osvdb_id(58503, 58504, 58505, 58506, 58507, 58508, 58509, 62327, 62328);
  script_xref(name:"DSA", value:"2000");

  script_name(english:"Debian DSA-2000-1 : ffmpeg-debian - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in ffmpeg, a multimedia
player, server and encoder, which also provides a range of multimedia
libraries used in applications like MPlayer :

Various programming errors in container and codec implementations may
lead to denial of service or the execution of arbitrary code if the
user is tricked into opening a malformed media file or stream.

The implementations of the following affected codecs and container
formats have been updated :

  - the Vorbis audio codec
  - the Ogg container implementation

  - the FF Video 1 codec

  - the MPEG audio codec

  - the H264 video codec

  - the MOV container implementation

  - the Oggedc container implementation"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2000"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ffmpeg packages.

For the stable distribution (lenny), these problems have been fixed in
version 0.svn20080206-18+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-debian");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/18");
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
if (deb_check(release:"5.0", prefix:"ffmpeg", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ffmpeg-dbg", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ffmpeg-doc", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavcodec-dev", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavcodec51", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavdevice-dev", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavdevice52", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavformat-dev", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavformat52", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavutil-dev", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libavutil49", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpostproc-dev", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpostproc51", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libswscale-dev", reference:"0.svn20080206-18+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libswscale0", reference:"0.svn20080206-18+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
