#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1132. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22674);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/09/25 10:51:09 $");

  script_cve_id("CVE-2006-3747");
  script_osvdb_id(27588);
  script_xref(name:"CERT", value:"395412");
  script_xref(name:"DSA", value:"1132");

  script_name(english:"Debian DSA-1132-1 : apache2 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mark Dowd discovered a buffer overflow in the mod_rewrite component of
apache, a versatile high-performance HTTP server. In some situations a
remote attacker could exploit this to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=380182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1132"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 package.

For the stable distribution (sarge) this problem has been fixed in
version 2.0.54-5sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Module mod_rewrite LDAP Protocol Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"apache2", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-common", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-doc", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-perchild", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-prefork", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-threadpool", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-mpm-worker", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-prefork-dev", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-threaded-dev", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache2-utils", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libapr0", reference:"2.0.54-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libapr0-dev", reference:"2.0.54-5sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
