#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-725. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18304);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/05/06 11:35:45 $");

  script_cve_id("CVE-2005-0392");
  script_osvdb_id(16686);
  script_xref(name:"DSA", value:"725");

  script_name(english:"Debian DSA-725-2 : ppxp - missing privilege release");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jens Steube discovered that ppxp, yet another PPP program, does not
release root privileges when opening potentially user-supplied log
files. This can be tricked into opening a root shell."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-725"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ppxp package.

For the old stable distribution (woody) this problem has been fixed in
version 0.2001080415-6woody2 (DSA 725-1).

For the stable distribution (sarge) this problem has been fixed in
version 0.2001080415-10sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppxp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/19");
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
if (deb_check(release:"3.0", prefix:"ppxp", reference:"0.2001080415-6woody2")) flag++;
if (deb_check(release:"3.0", prefix:"ppxp-dev", reference:"0.2001080415-6woody2")) flag++;
if (deb_check(release:"3.0", prefix:"ppxp-tcltk", reference:"0.2001080415-6woody2")) flag++;
if (deb_check(release:"3.0", prefix:"ppxp-x11", reference:"0.2001080415-6woody2")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp", reference:"0.2001080415-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp-dev", reference:"0.2001080415-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp-tcltk", reference:"0.2001080415-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp-x11", reference:"0.2001080415-10sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
