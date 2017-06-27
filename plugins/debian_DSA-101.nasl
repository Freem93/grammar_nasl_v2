#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-101. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14938);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_cve_id("CVE-2002-0043");
  script_xref(name:"DSA", value:"101");

  script_name(english:"Debian DSA-101-1 : sudo - Local root exploit");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sebastian Krahmer from SuSE found a vulnerability in sudo which could
easily lead into a local root exploit."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-101"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sudo packages immediately.

This problem has been fixed in upstream version 1.6.4 as well as in
version 1.6.2p2-2.1 for the stable release of Debian GNU/Linux."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/14");
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
if (deb_check(release:"2.2", prefix:"sudo", reference:"1.6.2p2-2.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
