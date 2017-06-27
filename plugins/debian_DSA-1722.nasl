#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1722. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35663);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0360", "CVE-2009-0361");
  script_osvdb_id(54343, 54344);
  script_xref(name:"DSA", value:"1722");

  script_name(english:"Debian DSA-1722-1 : libpam-heimdal - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Derek Chan discovered that the PAM module for the Heimdal Kerberos
implementation allows reinitialisation of user credentials when run
from a setuid context, resulting in potential local denial of service
by overwriting the credential cache file or to local privilege
escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1722"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpam-heimdal package.

For the stable distribution (etch), this problem has been fixed in
version 2.5-1etch1.

For the upcoming stable distribution (lenny), this problem has been
fixed in version 3.10-2.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_cwe_id(264, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libpam-heimdal", reference:"2.5-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
