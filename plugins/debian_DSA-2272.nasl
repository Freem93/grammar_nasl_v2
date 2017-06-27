#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2272. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55516);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2011-2464");
  script_osvdb_id(73605);
  script_xref(name:"DSA", value:"2272");

  script_name(english:"Debian DSA-2272-1 : bind9 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that BIND, a DNS server, does not correctly process
certain UPDATE requests, resulting in a server crash and a denial of
service. This vulnerability affects BIND installations even if they do
not actually use dynamic DNS updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2272"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:9.6.ESV.R4+dfsg-0+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"bind9", reference:"1:9.6.ESV.R4+dfsg-0+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"bind9", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"1:9.7.3.dfsg-1~squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
