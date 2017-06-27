#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1561. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32085);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:45:46 $");

  script_cve_id("CVE-2008-1293");
  script_osvdb_id(44681);
  script_xref(name:"DSA", value:"1561");

  script_name(english:"Debian DSA-1561-1 : ldm - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Herzog discovered that within the Linux Terminal Server
Project, it was possible to connect to X on any LTSP client from any
host on the network, making client windows and keystrokes visible to
that host.

NOTE: most ldm installs are likely to be in a chroot environment
exported over NFS, and will not be upgraded merely by upgrading the
server itself. For example, on the i386 architecture, to upgrade ldm
will likely require :

    chroot /opt/ltsp/i386 apt-get update chroot /opt/ltsp/i386 apt-get
    dist-upgrade"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=469462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1561"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ldm package.

For the stable distribution (etch), this problem has been fixed in
version 0.99debian11+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/01");
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
if (deb_check(release:"4.0", prefix:"ldm", reference:"0.99debian11+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ltsp-client", reference:"0.99debian11+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ltsp-server", reference:"0.99debian11+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ltsp-server-standalone", reference:"0.99debian11+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
