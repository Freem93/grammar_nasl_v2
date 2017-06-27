#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-964. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22830);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:19:44 $");

  script_cve_id("CVE-2006-0467");
  script_bugtraq_id(16429);
  script_osvdb_id(22791);
  script_xref(name:"DSA", value:"964");

  script_name(english:"Debian DSA-964-1 : gnocatan - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A problem has been discovered in gnocatan, the computer version of the
settlers of Catan boardgame, that can lead the server and other
clients to exit via an assert, and hence does not permit the execution
of arbitrary code. The game has been renamed into Pioneers after the
release of Debian sarge."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=350237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-964"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnocatan and pioneers packages.

For the old stable distribution (woody) this problem has been fixed in
version 0.6.1-5woody3.

For the stable distribution (sarge) this problem has been fixed in
version 0.8.1.59-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnocatan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/28");
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
if (deb_check(release:"3.0", prefix:"gnocatan-client", reference:"0.6.1-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"gnocatan-data", reference:"0.6.1-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"gnocatan-help", reference:"0.6.1-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"gnocatan-server", reference:"0.6.1-5woody3")) flag++;
if (deb_check(release:"3.1", prefix:"gnocatan-ai", reference:"0.8.1.59-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnocatan-client", reference:"0.8.1.59-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnocatan-help", reference:"0.8.1.59-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnocatan-meta-server", reference:"0.8.1.59-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnocatan-server-console", reference:"0.8.1.59-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnocatan-server-data", reference:"0.8.1.59-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gnocatan-server-gtk", reference:"0.8.1.59-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
