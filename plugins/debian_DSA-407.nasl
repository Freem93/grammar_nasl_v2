#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-407. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15244);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2003-0925", "CVE-2003-0926", "CVE-2003-0927", "CVE-2003-1012", "CVE-2003-1013");
  script_bugtraq_id(9248, 9249);
  script_xref(name:"DSA", value:"407");

  script_name(english:"Debian DSA-407-1 : ethereal - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered upstream in ethereal, a
network traffic analyzer. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CAN-2003-0925
    A buffer overflow allows remote attackers to cause a
    denial of service and possibly execute arbitrary code
    via a malformed GTP MSISDN string.

  - CAN-2003-0926

    Via certain malformed ISAKMP or MEGACO packets remote
    attackers are able to cause a denial of service (crash).

  - CAN-2003-0927

    A heap-based buffer overflow allows remote attackers to
    cause a denial of service (crash) and possibly execute
    arbitrary code via the SOCKS dissector.

  - CAN-2003-1012

    The SMB dissector allows remote attackers to cause a
    denial of service via a malformed SMB packet that
    triggers a segmentation fault during processing of
    selected packets.

  - CAN-2003-1013

    The Q.931 dissector allows remote attackers to cause a
    denial of service (crash) via a malformed Q.931, which
    triggers a null dereference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-407"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ethereal and tethereal packages.

For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"ethereal", reference:"0.9.4-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-common", reference:"0.9.4-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-dev", reference:"0.9.4-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"tethereal", reference:"0.9.4-1woody6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
