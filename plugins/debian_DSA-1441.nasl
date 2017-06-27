#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1441. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29808);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2007-6454");
  script_osvdb_id(40250);
  script_xref(name:"DSA", value:"1441");

  script_name(english:"Debian DSA-1441-1 : peercast - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Luigi Auriemma discovered that PeerCast, a P2P audio and video
streaming server, is vulnerable to a heap overflow in the HTTP server
code, which allows remote attackers to cause a denial of service and
possibly execute arbitrary code via a long SOURCE request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=457300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1441"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the peercast packages.

The old stable distribution (sarge) does not contain peercast.

For the stable distribution (etch), this problem has been fixed in
version 0.1217.toots.20060314-1etch0."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:peercast");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libpeercast0", reference:"0.1217.toots.20060314-1etch0")) flag++;
if (deb_check(release:"4.0", prefix:"libpeercast0-dev", reference:"0.1217.toots.20060314-1etch0")) flag++;
if (deb_check(release:"4.0", prefix:"peercast", reference:"0.1217.toots.20060314-1etch0")) flag++;
if (deb_check(release:"4.0", prefix:"peercast-handlers", reference:"0.1217.toots.20060314-1etch0")) flag++;
if (deb_check(release:"4.0", prefix:"peercast-servent", reference:"0.1217.toots.20060314-1etch0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
