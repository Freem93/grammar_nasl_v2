#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2244. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55032);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-1910");
  script_bugtraq_id(48007);
  script_xref(name:"DSA", value:"2244");

  script_name(english:"Debian DSA-2244-1 : bind9 - incorrect boundary condition");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that BIND, an implementation of the DNS protocol,
does not correctly process certain large RRSIG record sets in DNSSEC
responses. The resulting assertion failure causes the name server
process to crash, making name resolution unavailable. (CVE-2011-1910 )

In addition, this update fixes handling of certain signed/unsigned
zone combinations when a DLV service is used. Previously, data from
certain affected zones could become unavailable from the resolver."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2244"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:9.6.ESV.R4+dfsg-0+lenny2.

For the stable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"bind9", reference:"1:9.6.ESV.R4+dfsg-0+lenny2")) flag++;
if (deb_check(release:"6.0", prefix:"bind9", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"1:9.7.3.dfsg-1~squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
