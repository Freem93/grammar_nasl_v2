#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1200. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22927);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-4811");
  script_bugtraq_id(20599);
  script_osvdb_id(29843);
  script_xref(name:"DSA", value:"1200");

  script_name(english:"Debian DSA-1200-1 : qt-x11-free - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow has been found in the pixmap handling routines in
the Qt GUI libraries. This could allow an attacker to cause a denial
of service and possibly execute arbitrary code by providing a
specially crafted image file and inducing the victim to view it in an
application based on Qt."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=394313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1200"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qt-x11-free packages.

For the stable distribution (sarge), this problem has been fixed in
version 3:3.3.4-3sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt-x11-free");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/18");
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
if (deb_check(release:"3.1", prefix:"libqt3-compat-headers", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-dev", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-headers", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-i18n", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-mt-dev", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-ibase", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-ibase", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-mysql", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-odbc", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-psql", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-sqlite", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mysql", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-odbc", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-psql", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-sqlite", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-apps-dev", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-assistant", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-designer", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-dev-tools", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-dev-tools-compat", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-dev-tools-embedded", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-doc", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-examples", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-linguist", reference:"3:3.3.4-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-qtconfig", reference:"3:3.3.4-3sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
