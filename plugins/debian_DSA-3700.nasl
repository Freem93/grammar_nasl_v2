#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3700. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94259);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2015-3008", "CVE-2016-2232", "CVE-2016-2316", "CVE-2016-7551");
  script_osvdb_id(120492, 134040, 134041, 144030);
  script_xref(name:"DSA", value:"3700");

  script_name(english:"Debian DSA-3700-1 : asterisk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Asterisk, an open
source PBX and telephony toolkit, which may result in denial of
service or incorrect certificate validation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3700"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the stable distribution (jessie), these problems have been fixed
in version 1:11.13.1~dfsg-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
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
if (deb_check(release:"8.0", prefix:"asterisk", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-config", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dahdi", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dbg", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dev", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-doc", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mobile", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-modules", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mp3", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mysql", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-ooh323", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-imapstorage", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-vpb", reference:"1:11.13.1~dfsg-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
