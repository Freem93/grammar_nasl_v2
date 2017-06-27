#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2336. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56727);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-3362", "CVE-2011-3504", "CVE-2011-3973", "CVE-2011-3974");
  script_bugtraq_id(49115, 49118, 50555);
  script_osvdb_id(74926, 75621, 76802, 76803);
  script_xref(name:"DSA", value:"2336");

  script_name(english:"Debian DSA-2336-1 : ffmpeg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in FFmpeg, a multimedia player,
server and encoder :

  - CVE-2011-3362
    An integer signedness error in decode_residual_block
    function of the Chinese AVS video (CAVS) decoder in
    libavcodec can lead to denial of service (memory
    corruption and application crash) or possible code
    execution via a crafted CAVS file.

  - CVE-2011-3973/ CVE-2011-3974
    Multiple errors in the Chinese AVS video (CAVS) decoder
    can lead to denial of service (memory corruption and
    application crash) via an invalid bitstream.

  - CVE-2011-3504
    A memory allocation problem in the Matroska format
    decoder can lead to code execution via a crafted file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=641478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/ffmpeg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2336"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ffmpeg packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4:0.5.5-1.

Security support for ffmpeg has been discontinued for the oldstable
distribution (lenny) before in DSA 2306. The current version in
oldstable is not supported by upstream anymore and is affected by
several security issues. Backporting fixes for these and any future
issues has become unfeasible and therefore we needed to drop our
security support for the version in oldstable."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"ffmpeg", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-dbg", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-doc", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec-dev", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec52", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice-dev", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice52", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter-dev", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter0", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat-dev", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat52", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil-dev", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil49", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc-dev", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc51", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale-dev", reference:"4:0.5.5-1")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale0", reference:"4:0.5.5-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
