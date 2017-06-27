#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-960. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22826);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:19:44 $");

  script_cve_id("CVE-2005-4536");
  script_osvdb_id(22814);
  script_xref(name:"DSA", value:"960");

  script_name(english:"Debian DSA-960-3 : libmail-audit-perl - insecure temporary file creation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The former update caused temporary files to be created in the current
working directory due to a wrong function argument. This update will
create temporary files in the users home directory if HOME is set or
in the common temporary directory otherwise, usually /tmp. For
completeness below is a copy of the original advisory text :

  Niko Tyni discovered that the Mail::Audit module, a Perl library for
  creating simple mail filters, logs to a temporary file with a
  predictable filename in an insecure fashion when logging is turned
  on, which is not the case by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=344029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-960"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libmail-audit-perl package.

For the old stable distribution (woody) these problems have been fixed
in version 2.0-4woody3.

For the stable distribution (sarge) these problems have been fixed in
version 2.1-5sarge4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmail-audit-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/31");
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
if (deb_check(release:"3.0", prefix:"libmail-audit-perl", reference:"2.0-4woody3")) flag++;
if (deb_check(release:"3.0", prefix:"mail-audit-tools", reference:"2.0-4woody3")) flag++;
if (deb_check(release:"3.1", prefix:"libmail-audit-perl", reference:"2.1-5sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"mail-audit-tools", reference:"2.1-5sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
