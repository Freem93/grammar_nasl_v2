#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1536. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31721);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-1246", "CVE-2007-1387", "CVE-2008-0073", "CVE-2008-0486", "CVE-2008-1161");
  script_bugtraq_id(22771, 27441, 28312);
  script_osvdb_id(43119);
  script_xref(name:"DSA", value:"1536");

  script_name(english:"Debian DSA-1536-1 : libxine - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in Xine, a media
player library, allowed for a denial of service or arbitrary code
execution, which could be exploited through viewing malicious content.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2007-1246 / CVE-2007-1387
    The DMO_VideoDecoder_Open function does not set the
    biSize before use in a memcpy, which allows
    user-assisted remote attackers to cause a buffer
    overflow and possibly execute arbitrary code (applies to
    sarge only).

  - CVE-2008-0073
    Array index error in the sdpplin_parse function allows
    remote RTSP servers to execute arbitrary code via a
    large streamid SDP parameter.

  - CVE-2008-0486
    Array index vulnerability in libmpdemux/demux_audio.c
    might allow remote attackers to execute arbitrary code
    via a crafted FLAC tag, which triggers a buffer overflow
    (applies to etch only).

  - CVE-2008-1161
    Buffer overflow in the Matroska demuxer allows remote
    attackers to cause a denial of service (crash) and
    possibly execute arbitrary code via a Matroska file with
    invalid frame sizes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=464696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1536"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xine-lib package.

For the old stable distribution (sarge), these problems have been
fixed in version 1.0.1-1sarge7.

For the stable distribution (etch), these problems have been fixed in
version 1.1.2+dfsg-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/01");
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
if (deb_check(release:"3.1", prefix:"libxine-dev", reference:"1.0.1-1sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"libxine1", reference:"1.0.1-1sarge7")) flag++;
if (deb_check(release:"4.0", prefix:"libxine-dev", reference:"1.1.2+dfsg-6")) flag++;
if (deb_check(release:"4.0", prefix:"libxine1", reference:"1.1.2+dfsg-6")) flag++;
if (deb_check(release:"4.0", prefix:"libxine1-dbg", reference:"1.1.2+dfsg-6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
