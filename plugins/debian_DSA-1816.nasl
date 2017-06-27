#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1816. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39439);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-1195");
  script_bugtraq_id(35115);
  script_xref(name:"DSA", value:"1816");

  script_name(english:"Debian DSA-1816-1 : apache2 - insufficient security check");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Apache web server did not properly handle
the 'Options=' parameter to the AllowOverride directive :

  - In the stable distribution (lenny), local users could
    (via .htaccess) enable script execution in Server Side
    Includes even in configurations where the AllowOverride
    directive contained only Options=IncludesNoEXEC.
  - In the oldstable distribution (etch), local users could
    (via .htaccess) enable script execution in Server Side
    Includes and CGI script execution in configurations
    where the AllowOverride directive contained any
    'Options=' value.

The oldstable distribution (etch), this problem has been fixed in
version 2.2.3-4+etch8."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1816"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.2.9-10+lenny3.

This advisory also provides updated apache2-mpm-itk packages which
have been recompiled against the new apache2 packages (except for the
s390 architecture where updated packages will follow shortly)."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"apache2", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-doc", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-event", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-itk", reference:"2.2.3-01-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-perchild", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-prefork", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-worker", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-prefork-dev", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-src", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-threaded-dev", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-utils", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"apache2.2-common", reference:"2.2.3-4+etch8")) flag++;
if (deb_check(release:"5.0", prefix:"apache2", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-dbg", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-doc", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-event", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-itk", reference:"2.2.6-02-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-prefork", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-worker", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-prefork-dev", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-src", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec-custom", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-threaded-dev", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-utils", reference:"2.2.9-10+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"apache2.2-common", reference:"2.2.9-10+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
