#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1674. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34975);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/05/17 23:49:55 $");

  script_cve_id("CVE-2008-5139");
  script_osvdb_id(49965);
  script_xref(name:"DSA", value:"1674");

  script_name(english:"Debian DSA-1674-1 : jailer - insecure temp file generation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javier Fernandez-Sanguino Pena discovered that updatejail, a component
of the chroot maintenance tool Jailer, creates a predictable temporary
file name, which may lead to local denial of service through a symlink
attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=410548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1674"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the jailer package.

For the stable distribution (etch), this problem has been fixed in
version 0.4-9+etch1.

For the upcoming stable distribution (lenny) and the unstable
distribution (sid), this problem has been fixed in version 0.4-10."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jailer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"jailer", reference:"0.4-9+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
