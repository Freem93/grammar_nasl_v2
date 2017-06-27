#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1677. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35011);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2008-5286");
  script_bugtraq_id(32518);
  script_xref(name:"DSA", value:"1677");

  script_name(english:"Debian DSA-1677-1 : cupsys - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow has been discovered in the image validation code
of cupsys, the Common UNIX Printing System. An attacker could trigger
this bug by supplying a malicious graphic that could lead to the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=507183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1677"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cupsys packages.

For the stable distribution (etch) this problem has been fixed in
version 1.2.7-4etch6.

For testing distribution (lenny) this issue will be fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/03");
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
if (deb_check(release:"4.0", prefix:"cupsys", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-bsd", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-client", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-common", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-dbg", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2-dev", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-dev", reference:"1.2.7-4etch6")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-gnutls10", reference:"1.2.7-4etch6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
