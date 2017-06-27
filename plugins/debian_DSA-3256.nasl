#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3256. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83308);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/08/03 13:48:53 $");

  script_cve_id("CVE-2015-3622");
  script_bugtraq_id(74419);
  script_osvdb_id(121517);
  script_xref(name:"DSA", value:"3256");

  script_name(english:"Debian DSA-3256-1 : libtasn1-6 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hanno Boeck discovered a heap-based buffer overflow flaw in the way
Libtasn1, a library to manage ASN.1 structures, decoded certain
DER-encoded input. A specially crafted DER-encoded input could cause
an application using the Libtasn1 library to crash, or potentially to
execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libtasn1-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3256"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtasn1-6 packages.

For the stable distribution (jessie), this problem has been fixed in
version 4.2-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtasn1-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libtasn1-3-bin", reference:"4.2-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6", reference:"4.2-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6-dbg", reference:"4.2-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6-dev", reference:"4.2-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-bin", reference:"4.2-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-doc", reference:"4.2-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
