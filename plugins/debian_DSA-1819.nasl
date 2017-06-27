#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1819. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39451);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2008-1768", "CVE-2008-1769", "CVE-2008-1881", "CVE-2008-2147", "CVE-2008-2430", "CVE-2008-3794", "CVE-2008-4686", "CVE-2008-5032");
  script_bugtraq_id(32125);
  script_xref(name:"DSA", value:"1819");

  script_name(english:"Debian DSA-1819-1 : vlc - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in vlc, a multimedia
player and streamer. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2008-1768
    Drew Yao discovered that multiple integer overflows in
    the MP4 demuxer, Real demuxer and Cinepak codec can lead
    to the execution of arbitrary code.

  - CVE-2008-1769
    Drew Yao discovered that the Cinepak codec is prone to a
    memory corruption, which can be triggered by a crafted
    Cinepak file.

  - CVE-2008-1881
    Luigi Auriemma discovered that it is possible to execute
    arbitrary code via a long subtitle in an SSA file.

  - CVE-2008-2147
    It was discovered that vlc is prone to a search path
    vulnerability, which allows local users to perform
    privilege escalations.

  - CVE-2008-2430
    Alin Rad Pop discovered that it is possible to execute
    arbitrary code when opening a WAV file containing a
    large fmt chunk.

  - CVE-2008-3794
    Pinar Yanardag discovered that it is possible to
    execute arbitrary code when opening a crafted mmst link.

  - CVE-2008-4686
    Tobias Klein discovered that it is possible to execute
    arbitrary code when opening a crafted .ty file.

  - CVE-2008-5032
    Tobias Klein discovered that it is possible to execute
    arbitrary code when opening an invalid CUE image file
    with a crafted header."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=478140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=477805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=489004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=496265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=503118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=480724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1819"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the oldstable distribution (etch), these problems have been fixed
in version 0.8.6-svn20061012.debian-5.1+etch3.

For the stable distribution (lenny), these problems have been fixed in
version 0.8.6.h-4+lenny2, which was already included in the lenny
release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VLC Media Player RealText Subtitle Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libvlc0", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libvlc0-dev", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-plugin-vlc", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-nox", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-alsa", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-arts", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-esd", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-ggi", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-glide", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-sdl", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-svgalib", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"wxvlc", reference:"0.8.6-svn20061012.debian-5.1+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc", reference:"0.8.6.h-4+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
