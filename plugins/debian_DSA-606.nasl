#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-606. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15925);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1014");
  script_osvdb_id(12240);
  script_xref(name:"DSA", value:"606");

  script_name(english:"Debian DSA-606-1 : nfs-utils - wrong signal handler");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SGI has discovered that rpc.statd from the nfs-utils package, the
Network Status Monitor, did not ignore the 'SIGPIPE'. Hence, a client
prematurely terminating the TCP connection could also terminate the
server process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-606"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nfs-utils package.

For the stable distribution (woody) this problem has been fixed in
version 1.0-2woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"nfs-common", reference:"1.0-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"nfs-kernel-server", reference:"1.0-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"nhfsstone", reference:"1.0-2woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
