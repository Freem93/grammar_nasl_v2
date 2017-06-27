#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-761. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19224);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2231");
  script_osvdb_id(17892);
  script_xref(name:"DSA", value:"761");

  script_name(english:"Debian DSA-761-2 : heartbeat - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The security update DSA 761-1 for heartbeat contained a bug which
caused a regression.  This problem is corrected with this advisory.
 For completeness below please find the original advisory text :

  Eric Romang discovered several insecure temporary file creations in
  heartbeat, the subsystem for High-Availability Linux."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-761"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the heartbeat package.

For the old stable distribution (woody) these problems have been fixed
in version 0.4.9.0l-7.3.

For the stable distribution (sarge) these problems have been fixed in
version 1.2.3-9sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heartbeat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"heartbeat", reference:"0.4.9.0l-7.3")) flag++;
if (deb_check(release:"3.0", prefix:"ldirectord", reference:"0.4.9.0l-7.3")) flag++;
if (deb_check(release:"3.0", prefix:"libstonith-dev", reference:"0.4.9.0l-7.3")) flag++;
if (deb_check(release:"3.0", prefix:"libstonith0", reference:"0.4.9.0l-7.3")) flag++;
if (deb_check(release:"3.0", prefix:"stonith", reference:"0.4.9.0l-7.3")) flag++;
if (deb_check(release:"3.1", prefix:"heartbeat", reference:"1.2.3-9sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"heartbeat-dev", reference:"1.2.3-9sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ldirectord", reference:"1.2.3-9sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libpils-dev", reference:"1.2.3-9sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libpils0", reference:"1.2.3-9sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libstonith-dev", reference:"1.2.3-9sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libstonith0", reference:"1.2.3-9sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"stonith", reference:"1.2.3-9sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
