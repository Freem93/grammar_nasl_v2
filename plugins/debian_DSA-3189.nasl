#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3189. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81833);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");

  script_cve_id("CVE-2014-7933", "CVE-2014-8543", "CVE-2014-8544", "CVE-2014-8547", "CVE-2014-8548", "CVE-2014-9604");
  script_bugtraq_id(70876, 70880, 70884, 70888, 72272, 72288);
  script_osvdb_id(117390);
  script_xref(name:"DSA", value:"3189");

  script_name(english:"Debian DSA-3189-1 : libav - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been corrected in multiple demuxers and
decoders of the libav multimedia library. A full list of the changes
is available at"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libav"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3189"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libav packages.

For the stable distribution (wheezy), these problems have been fixed
in version 6:0.8.17-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ffmpeg", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"ffmpeg-dbg", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"ffmpeg-doc", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-dbg", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-doc", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-extra-dbg", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-tools", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec-dev", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec-extra-53", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec53", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice-dev", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice-extra-53", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice53", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter-dev", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter-extra-2", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter2", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat-dev", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat-extra-53", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat53", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil-dev", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil-extra-51", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil51", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc-dev", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc-extra-52", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc52", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale-dev", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale-extra-2", reference:"6:0.8.17-1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale2", reference:"6:0.8.17-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
