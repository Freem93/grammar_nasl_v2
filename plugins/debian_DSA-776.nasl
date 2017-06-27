#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-776. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19432);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-2450");
  script_bugtraq_id(14359);
  script_osvdb_id(18257, 18258, 18259);
  script_xref(name:"DSA", value:"776");

  script_name(english:"Debian DSA-776-1 : clamav - integer overflows, infinite loop");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several bugs were discovered in Clam AntiVirus, the antivirus scanner
for Unix, designed for integration with mail servers to perform
attachment scanning. The following problems were identified :

  - CAN-2005-2450
    Neel Mehta and Alex Wheeler discovered that Clam
    AntiVirus is vulnerable to integer overflows when
    handling the TNEF, CHM and FSG file formats.

  - CVE-NOMATCH

    Mark Pizzolato fixed a possible infinite loop that could
    cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-776"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav package.

The old stable distribution (woody) is not affected as it doesn't
contain clamav.

For the stable distribution (sarge) these problems have been fixed in
version 0.84-2.sarge.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/24");
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
if (deb_check(release:"3.1", prefix:"clamav", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-base", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-daemon", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-docs", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-freshclam", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-milter", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-testfiles", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"libclamav-dev", reference:"0.84-2.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"libclamav1", reference:"0.84-2.sarge.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
