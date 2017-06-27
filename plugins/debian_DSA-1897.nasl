#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1897. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44762);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2009-3236");
  script_xref(name:"DSA", value:"1897");

  script_name(english:"Debian DSA-1897-1 : horde3 - insufficient input sanitization");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Esser discovered that Horde, a web application framework
providing classes for dealing with preferences, compression, browser
detection, connection tracking, MIME, and more, is insufficiently
validating and escaping user provided input. The Horde_Form_Type_image
form element allows to reuse a temporary filename on reuploads which
are stored in a hidden HTML field and then trusted without prior
validation. An attacker can use this to overwrite arbitrary files on
the system or to upload PHP code and thus execute arbitrary code with
the rights of the webserver."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1897"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the horde3 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 3.1.3-4etch6.

For the stable distribution (lenny), this problem has been fixed in
version 3.2.2+debian0-2+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:horde3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"horde3", reference:"3.1.3-4etch6")) flag++;
if (deb_check(release:"5.0", prefix:"horde3", reference:"3.2.2+debian0-2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
