#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1941. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44806);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-0755", "CVE-2009-0756", "CVE-2009-3604", "CVE-2009-3605", "CVE-2009-3606", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3609", "CVE-2009-3903", "CVE-2009-3904", "CVE-2009-3905", "CVE-2009-3909", "CVE-2009-3938");
  script_bugtraq_id(36703, 36718, 36976);
  script_osvdb_id(51914, 55772, 59143, 59175, 59176, 59179, 59180, 59181, 59182, 59183, 59825, 59936);
  script_xref(name:"DSA", value:"1941");

  script_name(english:"Debian DSA-1941-1 : poppler - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several integer overflows, buffer overflows and memory allocation
errors were discovered in the Poppler PDF rendering library, which may
lead to denial of service or the execution of arbitrary code if a user
is tricked into opening a malformed PDF document.

An update for the old stable distribution (etch) will be issued soon
as version 0.4.5-5.1etch4."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1941"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the poppler packages.

For the stable distribution (lenny), these problems have been fixed in
version 0.8.7-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpoppler-dev", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-glib-dev", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-glib3", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt-dev", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt2", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt4-3", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler-qt4-dev", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"libpoppler3", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"poppler-dbg", reference:"0.8.7-3")) flag++;
if (deb_check(release:"5.0", prefix:"poppler-utils", reference:"0.8.7-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
