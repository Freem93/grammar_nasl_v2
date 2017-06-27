#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1828. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44693);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:49:57 $");

  script_cve_id("CVE-2009-0667");
  script_osvdb_id(55718);
  script_xref(name:"DSA", value:"1828");

  script_name(english:"Debian DSA-1828-1 : ocsinventory-agent - insecure module search path");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the ocsinventory-agent which is part of the
ocsinventory suite, a hardware and software configuration indexing
service, is prone to an insecure perl module search path. As the agent
is started via cron and the current directory (/ in this case) is
included in the default perl module path the agent scans every
directory on the system for its perl modules. This enables an attacker
to execute arbitrary code via a crafted ocsinventory-agent perl module
placed on the system.

The oldstable distribution (etch) does not contain ocsinventory-agent."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=506416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1828"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ocsinventory-agent packages.

For the stable distribution (lenny), this problem has been fixed in
version 1:0.0.9.2repack1-4lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocsinventory-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/07");
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
if (deb_check(release:"5.0", prefix:"ocsinventory-agent", reference:"1:0.0.9.2repack1-4lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
