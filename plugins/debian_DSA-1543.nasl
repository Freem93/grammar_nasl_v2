#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1543. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31949);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-6681", "CVE-2007-6682", "CVE-2007-6683", "CVE-2008-0073", "CVE-2008-0295", "CVE-2008-0296", "CVE-2008-0984", "CVE-2008-1489");
  script_osvdb_id(42193, 42194, 42205, 42206, 42207, 42208, 43702);
  script_xref(name:"DSA", value:"1543");

  script_name(english:"Debian DSA-1543-1 : vlc - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Luigi Auriemma, Alin Rad Pop, Remi Denis-Courmont, Quovodis, Guido
Landi, Felipe Manzano, Anibal Sacco and others discovered multiple
vulnerabilities in vlc, an application for playback and streaming of
audio and video. In the worst case, these weaknesses permit a remote,
unauthenticated attacker to execute arbitrary code with the privileges
of the user running vlc.

The Common Vulnerabilities and Exposures project identifies the
following eight problems :

  - CVE-2007-6681
    A buffer overflow vulnerability in subtitle handling
    allows an attacker to execute arbitrary code through the
    opening of a maliciously crafted MicroDVD, SSA or
    Vplayer file.

  - CVE-2007-6682
    A format string vulnerability in the HTTP-based remote
    control facility of the vlc application allows a remote,
    unauthenticated attacker to execute arbitrary code.

  - CVE-2007-6683
    Insecure argument validation allows a remote attacker to
    overwrite arbitrary files writable by the user running
    vlc, if a maliciously crafted M3U playlist or MP3 audio
    file is opened.

  - CVE-2008-0295, CVE-2008-0296
    Heap buffer overflows in RTSP stream and session
    description protocol (SDP) handling allow an attacker to
    execute arbitrary code if a maliciously crafted RTSP
    stream is played.

  - CVE-2008-0073
    Insufficient integer bounds checking in SDP handling
    allows the execution of arbitrary code through a
    maliciously crafted SDP stream ID parameter in an RTSP
    stream.

  - CVE-2008-0984
    Insufficient integrity checking in the MP4 demuxer
    allows a remote attacker to overwrite arbitrary memory
    and execute arbitrary code if a maliciously crafted MP4
    file is opened.

  - CVE-2008-1489
    An integer overflow vulnerability in MP4 handling allows
    a remote attacker to cause a heap buffer overflow,
    inducing a crash and possibly the execution of arbitrary
    code if a maliciously crafted MP4 file is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1543"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the stable distribution (etch), these problems have been fixed in
version 0.8.6-svn20061012.debian-5.1+etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/17");
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
if (deb_check(release:"4.0", prefix:"libvlc0", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libvlc0-dev", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-plugin-vlc", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-nox", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-alsa", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-arts", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-esd", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-ggi", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-glide", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-sdl", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-svgalib", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"wxvlc", reference:"0.8.6-svn20061012.debian-5.1+etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
