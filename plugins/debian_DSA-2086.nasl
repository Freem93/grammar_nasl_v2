#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2086. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48248);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2009-0758", "CVE-2010-2244");
  script_bugtraq_id(33946, 41075);
  script_xref(name:"DSA", value:"2086");

  script_name(english:"Debian DSA-2086-1 : avahi - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Avahi mDNS/DNS-SD
daemon. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2009-0758
    Rob Leslie discovered a denial of service vulnerability
    in the code used to reflect unicast mDNS traffic.

  - CVE-2010-2244
    Ludwig Nussel discovered a denial of service
    vulnerability in the processing of malformed DNS
    packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2086"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Avahi packages.

For the stable distribution (lenny), these problems have been fixed in
version 0.6.23-3lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"avahi-autoipd", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"avahi-daemon", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"avahi-dbg", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"avahi-discover", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"avahi-dnsconfd", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"avahi-ui-utils", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"avahi-utils", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-client-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-client3", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-common-data", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-common-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-common3", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-compat-howl-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-compat-howl0", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-compat-libdnssd-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-compat-libdnssd1", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-core-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-core5", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-glib-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-glib1", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-gobject-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-gobject0", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-qt3-1", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-qt3-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-qt4-1", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-qt4-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-ui-dev", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libavahi-ui0", reference:"0.6.23-3lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"python-avahi", reference:"0.6.23-3lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
