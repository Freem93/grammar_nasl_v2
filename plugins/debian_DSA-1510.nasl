#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1510. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31303);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2008-0411");
  script_osvdb_id(42310);
  script_xref(name:"DSA", value:"1510");

  script_name(english:"Debian DSA-1510-1 : ghostscript - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered a buffer overflow in the color space handling
code of the Ghostscript PostScript/PDF interpreter, which might result
in the execution of arbitrary code if a user is tricked into
processing a malformed file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1510"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gs-esp and gs-gpl packages.

For the stable distribution (etch), this problem has been fixed in
version 8.54.dfsg.1-5etch1 of gs-gpl and 8.15.3.dfsg.1-1etch1 of
gs-esp.

For the old stable distribution (sarge), this problem has been fixed
in version 8.01-6 of gs-gpl and 7.07.1-9sarge1 of gs-esp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gs-esp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gs-gpl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/28");
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
if (deb_check(release:"3.1", prefix:"gs", reference:"8.01-6")) flag++;
if (deb_check(release:"3.1", prefix:"gs-esp", reference:"7.07.1-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gs-gpl", reference:"8.01-6")) flag++;
if (deb_check(release:"4.0", prefix:"gs", reference:"8.54.dfsg.1-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gs-esp", reference:"8.15.3.dfsg.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gs-gpl", reference:"8.54.dfsg.1-5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
