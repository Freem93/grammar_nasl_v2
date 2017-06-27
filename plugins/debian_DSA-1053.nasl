#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1053. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22595);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_cve_id("CVE-2006-1993");
  script_bugtraq_id(17671);
  script_osvdb_id(24967);
  script_xref(name:"CERT", value:"866300");
  script_xref(name:"DSA", value:"1053");

  script_name(english:"Debian DSA-1053-1 : mozilla - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Martijn Wargers and Nick Mott described crashes of Mozilla due to the
use of a deleted controller context. In theory this could be abused to
execute malicious code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1053"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mozilla packages.

For the stable distribution (sarge) this problem has been fixed in
version 1.7.8-1sarge6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/23");
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
if (deb_check(release:"3.1", prefix:"libnspr-dev", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libnspr4", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libnss-dev", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libnss3", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-browser", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-calendar", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-chatzilla", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-dev", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-dom-inspector", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-js-debugger", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-mailnews", reference:"1.7.8-1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-psm", reference:"1.7.8-1sarge6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
