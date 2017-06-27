#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-653. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16237);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");
  script_osvdb_id(13108, 13109, 13110, 13111, 13112, 13113);
  script_xref(name:"DSA", value:"653");

  script_name(english:"Debian DSA-653-1 : ethereal - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow has been detected in the X11 dissector of ethereal,
a commonly used network traffic analyser. A remote attacker may be
able to overflow a buffer using a specially crafted IP packet. More
problems have been discovered which don't apply to the version in
woody but are fixed in sid as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-653"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ethereal package.

For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/20");
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
if (deb_check(release:"3.0", prefix:"ethereal", reference:"0.9.4-1woody11")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-common", reference:"0.9.4-1woody11")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-dev", reference:"0.9.4-1woody11")) flag++;
if (deb_check(release:"3.0", prefix:"tethereal", reference:"0.9.4-1woody11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
