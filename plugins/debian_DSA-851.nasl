#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-851. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19959);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2531", "CVE-2005-2532", "CVE-2005-2533", "CVE-2005-2534");
  script_osvdb_id(18882, 18883, 18884, 18885);
  script_xref(name:"DSA", value:"851");

  script_name(english:"Debian DSA-851-1 : openvpn - programming errors");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in openvpn, a
Virtual Private Network daemon. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CAN-2005-2531
    Wrong processing of failed certificate authentication
    when running with 'verb 0' and without TLS
    authentication can lead to a denial of service by
    disconnecting the wrong client.

  - CAN-2005-2532

    Wrong handling of packets that can't be decrypted on the
    server can lead to the disconnection of unrelated
    clients.

  - CAN-2005-2533

    When running in 'dev tap' Ethernet bridging mode,
    openvpn can exhaust its memory by receiving a large
    number of spoofed MAC addresses and hence denying
    service.

  - CAN-2005-2534

    Simultaneous TCP connections from multiple clients with
    the same client certificate can cause a denial of
    service when--duplicate-cn is not enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=324167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-851"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openvpn package.

The old stable distribution (woody) does not contain openvpn packages.

For the stable distribution (sarge) these problems have been fixed in
version 2.0-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"openvpn", reference:"2.0-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
