#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3758. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96460);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2016-9131", "CVE-2016-9147", "CVE-2016-9444");
  script_osvdb_id(149959, 149960, 149961);
  script_xref(name:"DSA", value:"3758");

  script_name(english:"Debian DSA-3758-1 : bind9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several denial-of-service vulnerabilities (assertion failures) were
discovered in BIND, a DNS server implementation.

  - CVE-2016-9131
    A crafted upstream response to an ANY query could cause
    an assertion failure.

  - CVE-2016-9147
    A crafted upstream response with self-contradicting
    DNSSEC data could cause an assertion failure.

  - CVE-2016-9444
    Specially crafted upstream responses with a DS record
    could cause an assertion failure.

These vulnerabilities predominantly affect DNS servers providing
recursive service. Client queries to authoritative-only servers cannot
trigger these assertion failures. These vulnerabilities are present
whether or not DNSSEC validation is enabled in the server
configuration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=851062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=851063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=851065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3758"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the stable distribution (jessie), these problems have been fixed
in version 1:9.9.5.dfsg-9+deb8u9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
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
if (deb_check(release:"8.0", prefix:"bind9", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"bind9-doc", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"bind9-host", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"bind9utils", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"dnsutils", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"host", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libbind-dev", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libbind-export-dev", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libbind9-90", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libdns-export100", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libdns-export100-udeb", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libdns100", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libirs-export91", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libirs-export91-udeb", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libisc-export95", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libisc-export95-udeb", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libisc95", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libisccc90", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libisccfg-export90", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libisccfg-export90-udeb", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libisccfg90", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"liblwres90", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"lwresd", reference:"1:9.9.5.dfsg-9+deb8u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
