#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1690. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35253);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2007-3372", "CVE-2008-5081");
  script_bugtraq_id(32825);
  script_osvdb_id(50929);
  script_xref(name:"DSA", value:"1690");

  script_name(english:"Debian DSA-1690-1 : avahi - assert errors");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two denial of service conditions were discovered in avahi, a Multicast
DNS implementation.

Huge Dias discovered that the avahi daemon aborts with an assert error
if it encounters a UDP packet with source port 0 (CVE-2008-5081 ).

It was discovered that the avahi daemon aborts with an assert error if
it receives an empty TXT record over D-Bus (CVE-2007-3372 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=508700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1690"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the avahi packages.

For the stable distribution (etch), these problems have been fixed in
version 0.6.16-3etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"avahi-autoipd", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"avahi-daemon", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"avahi-discover", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"avahi-dnsconfd", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"avahi-utils", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-client-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-client3", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-common-data", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-common-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-common3", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-compat-howl-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-compat-howl0", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-compat-libdnssd-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-compat-libdnssd1", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-core-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-core4", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-glib-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-glib1", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-qt3-1", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-qt3-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-qt4-1", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libavahi-qt4-dev", reference:"0.6.16-3etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python-avahi", reference:"0.6.16-3etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
