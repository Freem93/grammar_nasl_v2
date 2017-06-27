#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3603. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91616);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-3062");
  script_osvdb_id(139941);
  script_xref(name:"DSA", value:"3603");

  script_name(english:"Debian DSA-3603-1 : libav - security update");
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
is available at
https://git.libav.org/?p=libav.git;a=blob;f=Changelog;hb=refs/tags/v11
.7"
  );
  # https://git.libav.org/?p=libav.git;a=blob;f=Changelog;hb=refs/tags/v11.7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39466011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libav"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3603"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libav packages.

For the stable distribution (jessie), this problem has been fixed in
version 6:11.7-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libav-dbg", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libav-doc", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libav-tools", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-dev", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra-56", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec56", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice-dev", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice55", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter-dev", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter5", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat-dev", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat56", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample-dev", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample2", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil-dev", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil54", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale-dev", reference:"6:11.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale3", reference:"6:11.7-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
