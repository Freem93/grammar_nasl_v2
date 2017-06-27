#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1796. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38704);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-1364");
  script_bugtraq_id(34792);
  script_osvdb_id(56286);
  script_xref(name:"DSA", value:"1796");

  script_name(english:"Debian DSA-1796-1 : libwmf - pointer use-after-free");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered that the embedded GD library copy in libwmf,
a library to parse windows metafiles (WMF), makes use of a pointer
after it was already freed. An attacker using a crafted WMF file can
cause a denial of service or possibly the execute arbitrary code via
applications using this library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1796"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libwmf packages.

For the oldstable distribution (etch), this problem has been fixed in
version 0.2.8.4-2+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 0.2.8.4-6+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libwmf-bin", reference:"0.2.8.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwmf-dev", reference:"0.2.8.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwmf-doc", reference:"0.2.8.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwmf0.2-7", reference:"0.2.8.4-2+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libwmf-bin", reference:"0.2.8.4-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwmf-dev", reference:"0.2.8.4-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwmf-doc", reference:"0.2.8.4-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwmf0.2-7", reference:"0.2.8.4-6+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
