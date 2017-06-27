#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-281-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84990);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/06/15 16:38:32 $");

  script_cve_id("CVE-2015-1283");
  script_bugtraq_id(75973);
  script_osvdb_id(122039);

  script_name(english:"Debian DLA-281-1 : expat security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows in the XML_GetBuffer function in Expat
through 2.1.0, as used in Google Chrome before 44.0.2403.89 and other
products, allow remote attackers to cause a denial of service
(heap-based buffer overflow) or possibly have unspecified other impact
via crafted XML data, a related issue to CVE-2015-2716.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/expat"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64expat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64expat1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexpat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexpat1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexpat1-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");
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
if (deb_check(release:"6.0", prefix:"expat", reference:"2.0.1-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"lib64expat1", reference:"2.0.1-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"lib64expat1-dev", reference:"2.0.1-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libexpat1", reference:"2.0.1-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libexpat1-dev", reference:"2.0.1-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libexpat1-udeb", reference:"2.0.1-7+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
