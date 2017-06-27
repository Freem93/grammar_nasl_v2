#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3350. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85756);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/12/19 18:41:38 $");

  script_cve_id("CVE-2015-5722");
  script_osvdb_id(126995);
  script_xref(name:"DSA", value:"3350");

  script_name(english:"Debian DSA-3350-1 : bind9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hanno Boeck discovered that incorrect validation of DNSSEC-signed
records in the Bind DNS server could result in denial of service.

Updates for the oldstable distribution (wheezy) will be released
shortly."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3350"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the stable distribution (jessie), this problem has been fixed in
version 9.9.5.dfsg-9+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"bind9", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"bind9-doc", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"bind9-host", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"bind9utils", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"dnsutils", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"host", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbind-dev", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbind-export-dev", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbind9-90", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libdns-export100", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libdns-export100-udeb", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libdns100", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libirs-export91", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libirs-export91-udeb", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libisc-export95", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libisc-export95-udeb", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libisc95", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libisccc90", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libisccfg-export90", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libisccfg-export90-udeb", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libisccfg90", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"liblwres90", reference:"9.9.5.dfsg-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"lwresd", reference:"9.9.5.dfsg-9+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
