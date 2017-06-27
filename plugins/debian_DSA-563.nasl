#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-563. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15661);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0884", "CVE-2005-0373");
  script_osvdb_id(10554, 10555);
  script_xref(name:"DSA", value:"563");

  script_name(english:"Debian DSA-563-3 : cyrus-sasl - unsanitised input");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This advisory is an addition to DSA 563-1 and 563-2 which weren't able
to supersede the library on sparc and arm due to a different version
number for them in the stable archive. Other architectures were
updated properly. Another problem was reported in connection with
sendmail, though, which should be fixed with this update as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=275498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-563"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libsasl packages.

For the stable distribution (woody) this problem has been fixed in
version 1.5.27-3.1woody5.

For reference the advisory text follows :

  A vulnerability has been discovered in the Cyrus implementation of
  the SASL library, the Simple Authentication and Security Layer, a
  method for adding authentication support to connection-based
  protocols. The library honors the environment variable SASL_PATH
  blindly, which allows a local user to link against a malicious
  library to run arbitrary code with the privileges of a setuid or
  setgid application."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/08");
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
if (deb_check(release:"3.0", prefix:"libsasl-dev", reference:"1.5.27-3.1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libsasl-digestmd5-plain", reference:"1.5.27-3.1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libsasl-modules-plain", reference:"1.5.27-3.1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libsasl7", reference:"1.5.27-3.1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"sasl-bin", reference:"1.5.27-3.1woody5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
