#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3277. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83960);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2015-3808", "CVE-2015-3809", "CVE-2015-3810", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813", "CVE-2015-3814", "CVE-2015-3815", "CVE-2015-3906");
  script_bugtraq_id(74629, 74630, 74631, 74632, 74633, 74635, 74637);
  script_osvdb_id(119256, 122089, 122090, 122091, 122092);
  script_xref(name:"DSA", value:"3277");

  script_name(english:"Debian DSA-3277-1 : wireshark - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the dissectors/parsers for
LBMR, web sockets, WCP, X11, IEEE 802.11 and Android Logcat, which
could result in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3277"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.8.2-5wheezy16.

For the stable distribution (jessie), these problems have been fixed
in version 1.12.1+g01b65bf-4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libwireshark-data", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark-dev", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark2", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap-dev", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap2", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil-dev", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil2", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"tshark", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-common", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dbg", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dev", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-doc", reference:"1.8.2-5wheezy16")) flag++;
if (deb_check(release:"8.0", prefix:"libwireshark-data", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwireshark5", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwiretap-dev", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwiretap4", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwsutil-dev", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwsutil4", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tshark", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-common", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-dbg", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-doc", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"wireshark-qt", reference:"1.12.1+g01b65bf-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
