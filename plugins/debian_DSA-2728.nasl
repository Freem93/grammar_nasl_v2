#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2728. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69094);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2013-4854");
  script_osvdb_id(95707);
  script_xref(name:"DSA", value:"2728");

  script_name(english:"Debian DSA-2728-1 : bind9 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Maxim Shudrak and the HP Zero Day Initiative reported a denial of
service vulnerability in BIND, a DNS server. A specially crafted query
that includes malformed rdata can cause named daemon to terminate with
an assertion failure while rejecting the malformed query."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=717936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2728"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1:9.7.3.dfsg-1~squeeze11.

For the stable distribution (wheezy), this problem has been fixed in
version 1:9.8.4.dfsg.P1-6+nmu2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");
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
if (deb_check(release:"6.0", prefix:"bind9", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"1:9.7.3.dfsg-1~squeeze11")) flag++;
if (deb_check(release:"7.0", prefix:"bind9", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-doc", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"bind9utils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"dnsutils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbind-dev", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbind9-80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdns88", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libisc84", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libisccc80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libisccfg82", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"liblwres80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"lwresd", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
