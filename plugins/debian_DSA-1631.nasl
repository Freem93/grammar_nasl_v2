#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1631. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34033);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2008-3281");
  script_bugtraq_id(30783);
  script_xref(name:"DSA", value:"1631");

  script_name(english:"Debian DSA-1631-2 : libxml2 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andreas Solberg discovered that libxml2, the GNOME XML library, could
be forced to recursively evaluate entities, until available CPU and
memory resources were exhausted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1631"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 package.

For the stable distribution (etch), this problem has been fixed in
version 2.6.27.dfsg-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libxml2", reference:"2.6.27.dfsg-4")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dbg", reference:"2.6.27.dfsg-4")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dev", reference:"2.6.27.dfsg-4")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-doc", reference:"2.6.27.dfsg-4")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-utils", reference:"2.6.27.dfsg-4")) flag++;
if (deb_check(release:"4.0", prefix:"python-libxml2", reference:"2.6.27.dfsg-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
