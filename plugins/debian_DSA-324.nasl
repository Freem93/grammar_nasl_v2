#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-324. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15161);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:07:15 $");

  script_cve_id("CVE-2003-0428", "CVE-2003-0429", "CVE-2003-0431", "CVE-2003-0432");
  script_bugtraq_id(7878, 7880, 7881, 7883);
  script_xref(name:"DSA", value:"324");

  script_name(english:"Debian DSA-324-1 : ethereal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several of the packet dissectors in ethereal contain string handling
bugs which could be exploited using a maliciously crafted packet to
cause ethereal to consume excessive amounts of memory, crash, or
execute arbitrary code.

These vulnerabilities were announced in the following Ethereal
security advisory :

Ethereal 0.9.4 in Debian 3.0 (woody) is affected by most of the
problems described in the advisory, including :

  - The DCERPC dissector could try to allocate too much
    memory while trying to decode an NDR string.
  - Bad IPv4 or IPv6 prefix lengths could cause an overflow
    in the OSI dissector.

  - The tvb_get_nstringz0() routine incorrectly handled a
    zero-length buffer size.

  - The BGP, WTP, DNS, 802.11, ISAKMP, WSP, CLNP, and ISIS
    dissectors handled strings improperly.

The following problems do not affect this version :

  - The SPNEGO dissector could segfault while parsing an
    invalid ASN.1 value.
  - The RMI dissector handled strings improperly

as these modules are not present."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-324"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody5.

For the old stable distribution (potato) these problems will be fixed
in a future advisory.

We recommend that you update your ethereal package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/18");
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
if (deb_check(release:"3.0", prefix:"ethereal", reference:"0.9.4-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-common", reference:"0.9.4-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-dev", reference:"0.9.4-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"tethereal", reference:"0.9.4-1woody5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
