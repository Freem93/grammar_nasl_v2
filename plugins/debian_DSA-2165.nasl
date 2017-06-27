#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2165. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52028);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/03 11:25:18 $");

  script_cve_id("CVE-2010-3429", "CVE-2010-4704", "CVE-2010-4705");
  script_bugtraq_id(43546, 46294);
  script_osvdb_id(68269, 70650);
  script_xref(name:"DSA", value:"2165");

  script_name(english:"Debian DSA-2165-1 : ffmpeg-debian - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in FFmpeg coders, which
are used by MPlayer and other applications.

  - CVE-2010-3429
    Cesar Bernardini and Felipe Andres Manzano reported an
    arbitrary offset dereference vulnerability in the
    libavcodec, in particular in the FLIC file format
    parser. A specific FLIC file may exploit this
    vulnerability and execute arbitrary code. Mplayer is
    also affected by this problem, as well as other software
    that use this library.

  - CVE-2010-4704
    Greg Maxwell discovered an integer overflow the Vorbis
    decoder in FFmpeg. A specific Ogg file may exploit this
    vulnerability and execute arbitrary code.

  - CVE-2010-4705
    A potential integer overflow has been discovered in the
    Vorbis decoder in FFmpeg.

This upload also fixes an incomplete patch from DSA-2000-1. Michael
Gilbert noticed that there was remaining vulnerabilities, which may
cause a denial of service and potentially execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2165"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ffmpeg-debian packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.svn20080206-18+lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-debian");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"ffmpeg-debian", reference:"0.svn20080206-18+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
