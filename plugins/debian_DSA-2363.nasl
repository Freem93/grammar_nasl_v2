#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2363. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57503);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-2778");
  script_osvdb_id(77947);
  script_xref(name:"DSA", value:"2363");

  script_name(english:"Debian DSA-2363-1 : tor - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Tor, an online privacy tool, incorrectly
computes buffer sizes in certain cases involving SOCKS connections.
Malicious parties could use this to cause a heap-based buffer
overflow, potentially allowing execution of arbitrary code.

In Tor's default configuration this issue can only be triggered by
clients that can connect to Tor's SOCKS port, which listens only on
localhost by default.

In non-default configurations where Tor's SocksPort listens not only
on localhost or where Tor was configured to use another SOCKS server
for all of its outgoing connections, Tor is vulnerable to a larger set
of malicious parties."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2363"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tor packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.2.1.32-1.

For the stable distribution (squeeze), this problem has been fixed in
version 0.2.2.35-1~squeeze+1.

Please note that the update for stable (squeeze) updates this package
from 0.2.1.31 to 0.2.2.35, a new major release of Tor, as upstream has
announced end-of-life for the 0.2.1.x tree for the near future. Please
check your Tor runs as expected after the upgrade."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"tor", reference:"0.2.1.32-1")) flag++;
if (deb_check(release:"6.0", prefix:"tor", reference:"0.2.2.35-1~squeeze+1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-dbg", reference:"0.2.2.35-1~squeeze+1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-geoipdb", reference:"0.2.2.35-1~squeeze+1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
