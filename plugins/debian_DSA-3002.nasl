#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3002. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77111);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:48:47 $");

  script_cve_id("CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165");
  script_bugtraq_id(69000, 69001, 69002, 69003, 69005);
  script_xref(name:"DSA", value:"3002");

  script_name(english:"Debian DSA-3002-1 : wireshark - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the dissectors for
Catapult DCT2000, IrDA, GSM Management, RLC ASN.1 BER, which could
result in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3002"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.8.2-5wheezy11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libwireshark-data", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark-dev", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark2", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap-dev", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap2", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil-dev", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil2", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"tshark", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-common", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dbg", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dev", reference:"1.8.2-5wheezy11")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-doc", reference:"1.8.2-5wheezy11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
