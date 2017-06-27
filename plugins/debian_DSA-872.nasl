#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-872. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22738);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2005-2971");
  script_bugtraq_id(15060);
  script_osvdb_id(19909);
  script_xref(name:"DSA", value:"872");

  script_name(english:"Debian DSA-872-1 : koffice - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered a buffer overflow in the RTF importer of kword,
a word processor for the KDE Office Suite that can lead to the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=333497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-872"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kword package.

The old stable distribution (woody) does not contain a kword package.

For the stable distribution (sarge) this problem has been fixed in
version 1.3.5-4.sarge.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"karbon", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kchart", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kformula", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kivio", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kivio-data", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"koffice", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-data", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-dev", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-doc-html", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-libs", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"koshell", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kpresenter", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kspread", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kugar", reference:"1.3.5-4.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"kword", reference:"1.3.5-4.sarge.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
