#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2749. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69542);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-5641", "CVE-2013-5642");
  script_bugtraq_id(62021, 62022);
  script_osvdb_id(96690, 96691);
  script_xref(name:"DSA", value:"2749");

  script_name(english:"Debian DSA-2749-1 : asterisk - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Colin Cuthbertson and Walter Doekes discovered two vulnerabilities in
the SIP processing code of Asterisk - an open source PBX and telephony
toolkit -, which could result in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2749"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1:1.6.2.9-2+squeeze11.

For the stable distribution (wheezy), these problems have been fixed
in version 1.8.13.1~dfsg-3+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"asterisk", reference:"1:1.6.2.9-2+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-config", reference:"1:1.6.2.9-2+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dbg", reference:"1:1.6.2.9-2+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dev", reference:"1:1.6.2.9-2+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-doc", reference:"1:1.6.2.9-2+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-h323", reference:"1:1.6.2.9-2+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-sounds-main", reference:"1:1.6.2.9-2+squeeze11")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-config", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dahdi", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dbg", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dev", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-doc", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mobile", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-modules", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mp3", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mysql", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-ooh323", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail-imapstorage", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1.8.13.1~dfsg-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
