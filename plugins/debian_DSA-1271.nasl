#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1271. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24880);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:41:27 $");

  script_cve_id("CVE-2007-1507");
  script_osvdb_id(34368);
  script_xref(name:"DSA", value:"1271");

  script_name(english:"Debian DSA-1271-1 : openafs - design error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A design error has been identified in the OpenAFS, a cross-platform
distributed filesystem included with Debian.

OpenAFS historically has enabled setuid filesystem support for the
local cell. However, with its existing protocol, OpenAFS can only use
encryption, and therefore integrity protection, if the user is
authenticated. Unauthenticated access doesn't do integrity protection.
The practical result is that it's possible for an attacker with
knowledge of AFS to forge an AFS FetchStatus call and make an
arbitrary binary file appear to an AFS client host to be setuid. If
they can then arrange for that binary to be executed, they will be
able to achieve privilege escalation.

OpenAFS 1.3.81-3sarge2 changes the default behavior to disable setuid
files globally, including the local cell. It is important to note that
this change will not take effect until the AFS kernel module, built
from the openafs-modules-source package, is rebuilt and loaded into
your kernel. As a temporary workaround until the kernel module can be
reloaded, setuid support can be manually disabled for the local cell
by running the following command as root

fs setcell -cell <localcell> -nosuid

Following the application of this update, if you are certain there is
no security risk of an attacker forging AFS fileserver responses, you
can re-enable setuid status selectively with the following command,
however this should not be done on sites that are visible to the
Internet

fs setcell -cell <localcell> -suid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1271"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs package.

For the stable distribution (sarge), this problem has been fixed in
version 1.3.81-3sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libopenafs-dev", reference:"1.3.81-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libpam-openafs-kaserver", reference:"1.3.81-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-client", reference:"1.3.81-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-dbserver", reference:"1.3.81-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-fileserver", reference:"1.3.81-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-kpasswd", reference:"1.3.81-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-modules-source", reference:"1.3.81-3sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
