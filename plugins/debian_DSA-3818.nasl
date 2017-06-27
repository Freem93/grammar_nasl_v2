#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3818. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99004);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/31 13:26:14 $");

  script_cve_id("CVE-2016-9809", "CVE-2016-9812", "CVE-2016-9813", "CVE-2017-5843", "CVE-2017-5848");
  script_osvdb_id(147995, 147996, 148099, 151269, 151335);
  script_xref(name:"DSA", value:"3818");

  script_name(english:"Debian DSA-3818-1 : gst-plugins-bad1.0 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hanno Boeck discovered multiple vulnerabilities in the GStreamer media
framework and its codecs and demuxers, which may result in denial of
service or the execution of arbitrary code if a malformed media file
is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gst-plugins-bad1.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3818"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gst-plugins-bad1.0 packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.4.4-2.1+deb8u2.

For the upcoming stable distribution (stretch), these problems have
been fixed in version 1.10.4-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-bad1.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"gstreamer1.0-plugins-bad", reference:"1.4.4-2.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer1.0-plugins-bad-dbg", reference:"1.4.4-2.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer1.0-plugins-bad-doc", reference:"1.4.4-2.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad1.0-0", reference:"1.4.4-2.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad1.0-dev", reference:"1.4.4-2.1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
