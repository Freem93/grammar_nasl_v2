#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-933. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22799);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/18 00:19:44 $");

  script_cve_id("CVE-2005-3539");
  script_osvdb_id(22246);
  script_xref(name:"DSA", value:"933");

  script_name(english:"Debian DSA-933-1 : hylafax - arbitrary command execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Patrice Fournier found that hylafax passes unsanitized user data in
the notify script, allowing users with the ability to submit jobs to
run arbitrary commands with the privileges of the hylafax server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-933"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the hylafax package.

For the old stable distribution (woody) this problem has been fixed in
version 4.1.1-4woody1.

For the stable distribution (sarge) this problem has been fixed in
version 4.2.1-5sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hylafax");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/04");
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
if (deb_check(release:"3.0", prefix:"hylafax-client", reference:"4.1.1-4woody1")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-doc", reference:"4.1.1-4woody1")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-server", reference:"4.1.1-4woody1")) flag++;
if (deb_check(release:"3.1", prefix:"hylafax-client", reference:"4.2.1-5sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hylafax-doc", reference:"4.2.1-5sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hylafax-server", reference:"4.2.1-5sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
