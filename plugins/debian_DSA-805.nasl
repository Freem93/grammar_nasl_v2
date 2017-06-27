#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-805. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19612);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-1268", "CVE-2005-2088", "CVE-2005-2700", "CVE-2005-2728");
  script_bugtraq_id(14660);
  script_osvdb_id(17738, 18286, 18977, 19188);
  script_xref(name:"CERT", value:"744929");
  script_xref(name:"DSA", value:"805");

  script_name(english:"Debian DSA-805-1 : apache2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in Apache2, the next generation,
scalable, extendable web server. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CAN-2005-1268
    Marc Stern discovered an off-by-one error in the mod_ssl
    Certificate Revocation List (CRL) verification callback.
    When Apache is configured to use a CRL this can be used
    to cause a denial of service.

  - CAN-2005-2088

    A vulnerability has been discovered in the Apache web
    server. When it is acting as an HTTP proxy, it allows
    remote attackers to poison the web cache, bypass web
    application firewall protection, and conduct cross-site
    scripting attacks, which causes Apache to incorrectly
    handle and forward the body of the request.

  - CAN-2005-2700

    A problem has been discovered in mod_ssl, which provides
    strong cryptography (HTTPS support) for Apache that
    allows remote attackers to bypass access restrictions.

  - CAN-2005-2728

    The byte-range filter in Apache 2.0 allows remote
    attackers to cause a denial of service via an HTTP
    header with a large Range field."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=316173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=320048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=320063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=326435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-805"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

The old stable distribution (woody) does not contain Apache2 packages.

For the stable distribution (sarge) these problems have been fixed in
version 2.0.54-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/26");
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
if (deb_check(release:"3.1", prefix:"apache2", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-common", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-doc", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-perchild", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-prefork", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-threadpool", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-worker", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-prefork-dev", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-threaded-dev", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-utils", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"libapr0", reference:"2.0.54-5")) flag++;
if (deb_check(release:"3.1", prefix:"libapr0-dev", reference:"2.0.54-5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
