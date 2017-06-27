#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-266-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84508);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-1819");
  script_bugtraq_id(75570);
  script_osvdb_id(120600);

  script_name(english:"Debian DLA-266-1 : libxml2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This upload to Debian squeeze-lts fixes three issues found in the
libxml2 package.

(1) CVE-2015-1819 / #782782

Florian Weimer from Red Hat reported an issue against libxml2, where a
parser which uses libxml2 chokes on a crafted XML document, allocating
gigabytes of data. This is a fine line issue between API misuse and a
bug in libxml2. This issue got addressed in libxml2 upstream and the
patch has been backported to libxml2 in squeeze-lts.

(2) #782985

Jun Kokatsu reported an out-of-bounds memory access in libxml2. By
entering an unclosed html comment the libxml2 parser didn't stop
parsing at the end of the buffer, causing random memory to be included
in the parsed comment that was returned to the evoking application.

In the Shopify application (where this issue was originally
discovered), this caused ruby objects from previous http requests to
be disclosed in the rendered page.

(3) #783010

Michal Zalewski reported another out-of-bound reads issue in libxml2
that did not cause any crashes but could be detected under ASAN and
Valgrind.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libxml2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");
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
if (deb_check(release:"6.0", prefix:"libxml2", reference:"2.7.8.dfsg-2+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dev", reference:"2.7.8.dfsg-2+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-doc", reference:"2.7.8.dfsg-2+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-utils", reference:"2.7.8.dfsg-2+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2", reference:"2.7.8.dfsg-2+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
