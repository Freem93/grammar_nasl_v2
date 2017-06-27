#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-666. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16340);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2005-0089");
  script_osvdb_id(13468);
  script_xref(name:"DSA", value:"666");

  script_name(english:"Debian DSA-666-1 : python2.2 - design flaw");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Python development team has discovered a flaw in their language
package. The SimpleXMLRPCServer library module could permit remote
attackers unintended access to internals of the registered object or
its module or possibly other modules. The flaw only affects Python
XML-RPC servers that use the register_instance() method to register an
object without a _dispatch() method. Servers using only
register_function() are not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-666"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Python packages.

For the stable distribution (woody) this problem has been fixed in
version 2.2.1-4.7. No other version of Python in woody is affected.

                   testing          unstable         
  Python 2.2       2.2.3-14         2.2.3-14         
  Python 2.3       2.3.4-20         2.3.4+2.3.5c1-2  
  Python 2.4       2.4-5            2.4-5"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"idle-python2.2", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-dev", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-doc", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-elisp", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-examples", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-gdbm", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-mpz", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-tk", reference:"2.2.1-4.7")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-xmlbase", reference:"2.2.1-4.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
