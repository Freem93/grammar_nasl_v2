#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-853. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19961);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/08/20 15:05:35 $");

  script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");
  script_osvdb_id(18362, 18363, 18364, 18365, 18366, 18367, 18368, 18369, 18370, 18371, 18372, 18373, 18374, 18375, 18376, 18377, 18378, 18379, 18380, 18381, 18383, 18384, 18385, 18388, 18670);
  script_xref(name:"DSA", value:"853");

  script_name(english:"Debian DSA-853-1 : ethereal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security problems have been discovered in ethereal, a commonly
used network traffic analyser. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CAN-2005-2360
    Memory allocation errors in the LDAP dissector can cause
    a denial of service.

  - CAN-2005-2361

    Various errors in the AgentX, PER, DOCSIS, RADIUS,
    Telnet, IS-IS, HTTP, DCERPC, DHCP and SCTP dissectors
    can cause a denial of service.

  - CAN-2005-2363

    Various errors in the SMPP, 802.3, H1 and DHCP
    dissectors can cause a denial of service.

  - CAN-2005-2364

    NULL pointer dereferences in the WBXML and GIOP
    dissectors can cause a denial of service.

  - CAN-2005-2365

    A buffer overflow and NULL pointer dereferences in the
    SMB dissector can cause a denial of service.

  - CAN-2005-2366

    Wrong address calculation in the BER dissector can cause
    an infinite loop or abortion.

  - CAN-2005-2367

    Format string vulnerabilities in several dissectors
    allow remote attackers to write to arbitrary memory
    locations and thus gain privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-853"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ethereal packages.

For the old stable distribution (woody) these problems have been fixed
in version 0.9.4-1woody13.

For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"ethereal", reference:"0.9.4-1woody13")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-common", reference:"0.9.4-1woody13")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-dev", reference:"0.9.4-1woody13")) flag++;
if (deb_check(release:"3.0", prefix:"tethereal", reference:"0.9.4-1woody13")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal", reference:"0.10.10-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-common", reference:"0.10.10-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-dev", reference:"0.10.10-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"tethereal", reference:"0.10.10-2sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
