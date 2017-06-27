#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3746. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96103);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/28 15:10:48 $");

  script_cve_id("CVE-2015-8808", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-3714", "CVE-2016-3715", "CVE-2016-5118", "CVE-2016-5240", "CVE-2016-7800", "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684", "CVE-2016-9830");
  script_osvdb_id(134375, 134437, 134439, 134440, 134441, 134442, 134443, 137952, 137955, 137975, 139185, 145002, 145319, 145326, 145393, 145394, 145395, 147196, 147270);
  script_xref(name:"DSA", value:"3746");

  script_name(english:"Debian DSA-3746-1 : graphicsmagick - security update (ImageTragick)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in GraphicsMagick, a
collection of image processing tool, which can cause denial of service
attacks, remote file deletion, and remote command execution.

This security update removes the full support of PLT/Gnuplot decoder
to prevent Gnuplot-shell based shell exploits for fixing the
CVE-2016-3714 vulnerability.

The undocumented 'TMP' magick prefix no longer removes the argument
file after it has been read for fixing the CVE-2016-3715
vulnerability. Since the 'TMP' feature was originally implemented,
GraphicsMagick added a temporary file management subsystem which
assures that temporary files are removed so this feature is not
needed.

Remove support for reading input from a shell command, or writing
output to a shell command, by prefixing the specified filename
(containing the command) with a '|' for fixing the CVE-2016-5118
vulnerability.

  - CVE-2015-8808
    Gustavo Grieco discovered an out of bound read in the
    parsing of GIF files which may cause denial of service.

  - CVE-2016-2317
    Gustavo Grieco discovered a stack-based buffer overflow
    and two heap buffer overflows while processing SVG
    images which may cause denial of service.

  - CVE-2016-2318
    Gustavo Grieco discovered several segmentation faults
    while processing SVG images which may cause denial of
    service.

  - CVE-2016-5240
    Gustavo Grieco discovered an endless loop problem caused
    by negative stroke-dasharray arguments while parsing SVG
    files which may cause denial of service.

  - CVE-2016-7800
    Marco Grassi discovered an unsigned underflow leading to
    heap overflow when parsing 8BIM chunk often attached to
    JPG files which may cause denial of service.

  - CVE-2016-7996
    Moshe Kaplan discovered that there is no check that the
    provided colormap is not larger than 256 entries in the
    WPG reader which may cause denial of service.

  - CVE-2016-7997
    Moshe Kaplan discovered that an assertion is thrown for
    some files in the WPG reader due to a logic error which
    may cause denial of service.

  - CVE-2016-8682
    Agostino Sarubbo of Gentoo discovered a stack buffer
    read overflow while reading the SCT header which may
    cause denial of service.

  - CVE-2016-8683
    Agostino Sarubbo of Gentoo discovered a memory
    allocation failure in the PCX coder which may cause
    denial of service.

  - CVE-2016-8684
    Agostino Sarubbo of Gentoo discovered a memory
    allocation failure in the SGI coder which may cause
    denial of service.

  - CVE-2016-9830
    Agostino Sarubbo of Gentoo discovered a memory
    allocation failure in MagickRealloc() function which may
    cause denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=814732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=825800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/graphicsmagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3746"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the graphicsmagick packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.3.20-3+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");
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
if (deb_check(release:"8.0", prefix:"graphicsmagick", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-dbg", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphics-magick-perl", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick++3", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.20-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick3", reference:"1.3.20-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
