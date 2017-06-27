#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2378. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57518);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-4351", "CVE-2011-4353", "CVE-2011-4364", "CVE-2011-4579");
  script_bugtraq_id(50760, 50880);
  script_osvdb_id(77289, 77291, 78090, 78300);
  script_xref(name:"DSA", value:"2378");

  script_name(english:"Debian DSA-2378-1 : ffmpeg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in FFmpeg, a multimedia
player, server and encoder. Multiple input validations in the decoders
for QDM2, VP5, VP6, VMD and SVQ1 files could lead to the execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/ffmpeg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2378"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ffmpeg packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4:0.5.6-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"ffmpeg", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-dbg", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-doc", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec-dev", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec52", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice-dev", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice52", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter-dev", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter0", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat-dev", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat52", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil-dev", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil49", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc-dev", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc51", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale-dev", reference:"4:0.5.6-3")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale0", reference:"4:0.5.6-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
