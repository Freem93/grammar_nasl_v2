#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-781-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96459);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2014-2287");
  script_bugtraq_id(66094);
  script_osvdb_id(104326);

  script_name(english:"Debian DLA-781-2 : asterisk regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brad Barnett found that the recent security update of Asterisk could
cause immediate SIP termination due to an incomplete fix for
CVE-2014-2287.

For Debian 7 'Wheezy', these problems have been fixed in version
1:1.8.13.1~dfsg1-3+deb7u6.

We recommend that you upgrade your asterisk packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/asterisk"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-imapstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-odbcstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");
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
if (deb_check(release:"7.0", prefix:"asterisk", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-config", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dahdi", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dbg", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dev", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-doc", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mobile", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-modules", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mp3", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mysql", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-ooh323", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail-imapstorage", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1:1.8.13.1~dfsg1-3+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
