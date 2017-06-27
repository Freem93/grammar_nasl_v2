#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-975. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22841);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:19:44 $");

  script_cve_id("CVE-2006-0043");
  script_osvdb_id(22756);
  script_xref(name:"DSA", value:"975");

  script_name(english:"Debian DSA-975-1 : nfs-user-server - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marcus Meissner discovered that attackers can trigger a buffer
overflow in the path handling code by creating or abusing existing
symlinks, which may lead to the execution of arbitrary code.

This vulnerability isn't present in the kernel NFS server.

This update includes a bugfix for attribute handling of symlinks. This
fix does not have security implications, but at the time when this DSA
was prepared it was already queued for the next stable point release,
so we decided to include it beforehand."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=350020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nfs-user-server package.

For the old stable distribution (woody) this problem has been fixed in
version 2.2beta47-12woody1.

For the stable distribution (sarge) this problem has been fixed in
version 2.2beta47-20sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-user-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/26");
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
if (deb_check(release:"3.0", prefix:"nfs-user-server", reference:"2.2beta47-12woody1")) flag++;
if (deb_check(release:"3.0", prefix:"ugidd", reference:"2.2beta47-12woody1")) flag++;
if (deb_check(release:"3.1", prefix:"nfs-user-server", reference:"2.2beta47-20sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ugidd", reference:"2.2beta47-20sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
