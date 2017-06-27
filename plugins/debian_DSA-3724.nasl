#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3724. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95298);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/02/13 20:45:09 $");

  script_cve_id("CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636");
  script_osvdb_id(147688);
  script_xref(name:"DSA", value:"3724");

  script_name(english:"Debian DSA-3724-1 : gst-plugins-good0.10 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered that the GStreamer 0.10 plugin used to decode
files in the FLIC format allowed execution of arbitrary code. Further
details can be found in his advisory at
https://scarybeastsecurity.blogspot.de/2016/11/0day-exploit-advancing-
exploitation.html

This update removes the insecure FLIC file format plugin."
  );
  # https://scarybeastsecurity.blogspot.de/2016/11/0day-exploit-advancing-exploitation.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f35a079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gst-plugins-good0.10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3724"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gst-plugins-good0.10 packages.

For the stable distribution (jessie), these problems have been fixed
in version 0.10.31-3+nmu4+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-good0.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"gstreamer0.10-gconf", reference:"0.10.31-3+nmu4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer0.10-plugins-good", reference:"0.10.31-3+nmu4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer0.10-plugins-good-dbg", reference:"0.10.31-3+nmu4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer0.10-plugins-good-doc", reference:"0.10.31-3+nmu4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer0.10-pulseaudio", reference:"0.10.31-3+nmu4+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
