#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2517. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60156);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2012-3817");
  script_bugtraq_id(54658);
  script_osvdb_id(84228);
  script_xref(name:"DSA", value:"2517");

  script_name(english:"Debian DSA-2517-1 : bind9 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Einar Lonn discovered that under certain conditions bind9, a DNS
server, may use cached data before initialization. As a result, an
attacker can trigger an assertion failure on servers under high query
load that do DNSSEC validation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2517"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"bind9", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"1:9.7.3.dfsg-1~squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
