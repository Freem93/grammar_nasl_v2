#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1512. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31359);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2008-0072");
  script_osvdb_id(42804);
  script_xref(name:"DSA", value:"1512");

  script_name(english:"Debian DSA-1512-1 : evolution - format string attack");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ulf Harnhammar discovered that Evolution, the e-mail and groupware
suite, had a format string vulnerability in the parsing of encrypted
mail messages. If the user opened a specially crafted email message,
code execution was possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1512"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the evolution package.

For the stable distribution (etch), this problem has been fixed in
version 2.6.3-6etch2.

For the old stable distribution (sarge), this problem has been fixed
in version 2.0.4-2sarge3. Some architectures have not yet completed
building the updated package for sarge, they will be added as they
come available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"evolution", reference:"2.0.4-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"evolution-dev", reference:"2.0.4-2sarge3")) flag++;
if (deb_check(release:"4.0", prefix:"evolution", reference:"2.6.3-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-common", reference:"2.6.3-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-dbg", reference:"2.6.3-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-dev", reference:"2.6.3-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-plugins", reference:"2.6.3-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-plugins-experimental", reference:"2.6.3-6etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
