#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1398. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27628);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-5740");
  script_osvdb_id(42004);
  script_xref(name:"DSA", value:"1398");

  script_name(english:"Debian DSA-1398-1 : perdition - format string error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bernhard Mueller of SEC Consult has discovered a format string
vulnerability in perdition, an IMAP proxy. This vulnerability could
allow an unauthenticated remote user to run arbitrary code on the
perdition server by providing a specially formatted IMAP tag."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=448853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1398"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perdition package.

For the old stable distribution (sarge), this problem has been fixed
in version 1.15-5sarge1.

For the stable distribution (etch), this problem has been fixed in
version 1.17-7etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perdition");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"perdition", reference:"1.15-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"perdition-dev", reference:"1.15-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"perdition-ldap", reference:"1.15-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"perdition-mysql", reference:"1.15-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"perdition-odbc", reference:"1.15-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"perdition-postgresql", reference:"1.15-5sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"perdition", reference:"1.17-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perdition-dev", reference:"1.17-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perdition-ldap", reference:"1.17-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perdition-mysql", reference:"1.17-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perdition-odbc", reference:"1.17-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perdition-postgresql", reference:"1.17-7etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
