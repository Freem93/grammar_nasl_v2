#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-280-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84989);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2015-3228");
  script_bugtraq_id(76017);
  script_osvdb_id(125256);

  script_name(english:"Debian DLA-280-1 : ghostscript security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In gs_heap_alloc_bytes(), add a sanity check to ensure we don't
overflow the variable holding the actual number of bytes we allocate.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ghostscript"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gs-esp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gs-gpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs8");
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
if (deb_check(release:"6.0", prefix:"ghostscript", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"ghostscript-cups", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"ghostscript-doc", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"ghostscript-x", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gs-common", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gs-esp", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gs-gpl", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgs-dev", reference:"8.71~dfsg2-9+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgs8", reference:"8.71~dfsg2-9+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
