#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2494. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59772);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2011-3951", "CVE-2011-3952", "CVE-2012-0851", "CVE-2012-0852");
  script_bugtraq_id(51307, 51720);
  script_osvdb_id(78178, 78635, 78644, 83116);
  script_xref(name:"DSA", value:"2494");

  script_name(english:"Debian DSA-2494-1 : ffmpeg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that FFmpeg, Debian's version of the Libav media
codec suite, contains vulnerabilities in the DPCM codecs
(CVE-2011-3951 ), H.264 (CVE-2012-0851 ), ADPCM (CVE-2012-0852 ), and
the KMVC decoder (CVE-2011-3952 ).

In addition, this update contains bug fixes from the Libav 0.5.9
upstream release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/ffmpeg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2494"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ffmpeg packages.

For the stable distribution (squeeze), these problems have been fixed
in version 4:0.5.9-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
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
if (deb_check(release:"6.0", prefix:"ffmpeg", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-dbg", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-doc", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec-dev", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec52", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice-dev", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice52", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter-dev", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter0", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat-dev", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat52", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil-dev", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil49", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc-dev", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc51", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale-dev", reference:"4:0.5.9-1")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale0", reference:"4:0.5.9-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
