#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-373-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87605);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/07/06 14:12:40 $");

  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500");
  script_osvdb_id(130535, 130536, 130538, 130539, 130543);

  script_name(english:"Debian DLA-373-1 : libxml2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in libxml2, a library
providing support to read, modify and write XML and HTML files. A
remote attacker could provide a specially crafted XML or HTML file
that, when processed by an application using libxml2, would cause that
application to use an excessive amount of CPU, leak potentially
sensitive information, or crash the application.

CVE-2015-5312: CPU exhaustion when processing specially crafted XML
input. CVE-2015-7497: Heap-based buffer overflow in
xmlDictComputeFastQKey. CVE-2015-7498: Heap-based buffer overflow in
xmlParseXmlDecl. CVE-2015-7499: Heap-based buffer overflow in xmlGROW.
CVE-2015-7500: Heap buffer overflow in xmlParseMisc.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/12/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libxml2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libxml2", reference:"2.7.8.dfsg-2+squeeze16")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze16")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dev", reference:"2.7.8.dfsg-2+squeeze16")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-doc", reference:"2.7.8.dfsg-2+squeeze16")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-utils", reference:"2.7.8.dfsg-2+squeeze16")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2", reference:"2.7.8.dfsg-2+squeeze16")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
