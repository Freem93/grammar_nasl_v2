#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1382. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26975);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/08/23 20:55:06 $");

  script_cve_id("CVE-2007-4826");
  script_xref(name:"DSA", value:"1382");

  script_name(english:"Debian DSA-1382-1 : quagga - NULL pointer dereference");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that BGP peers can trigger a NULL pointer
dereference in the BGP daemon if debug logging is enabled, causing the
BGP daemon to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=442133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1382"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the quagga packages.

For the old stable distribution (sarge), this problem has been fixed
in version 0.98.3-7.5.

For the stable distribution (etch), this problem has been fixed in
version 0.99.5-5etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"quagga", reference:"0.98.3-7.5")) flag++;
if (deb_check(release:"3.1", prefix:"quagga-doc", reference:"0.98.3-7.5")) flag++;
if (deb_check(release:"4.0", prefix:"quagga", reference:"0.99.5-5etch3")) flag++;
if (deb_check(release:"4.0", prefix:"quagga-doc", reference:"0.99.5-5etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
