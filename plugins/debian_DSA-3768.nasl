#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3768. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96667);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2016-5159", "CVE-2016-8332", "CVE-2016-9572", "CVE-2016-9573");
  script_osvdb_id(133539, 142663, 142664, 146439, 146612);
  script_xref(name:"DSA", value:"3768");

  script_name(english:"Debian DSA-3768-1 : openjpeg2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities in OpenJPEG, a JPEG 2000 image compression /
decompression library, may result in denial of service or the
execution of arbitrary code if a malformed JPEG 2000 file is
processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openjpeg2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3768"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjpeg2 packages.

For the stable distribution (jessie), these problems have been fixed
in version 2.1.0-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/23");
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
if (deb_check(release:"8.0", prefix:"libopenjp2-7", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dbg", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dev", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-tools", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d-tools", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d7", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-dec-server", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-server", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-viewer", reference:"2.1.0-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip7", reference:"2.1.0-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
