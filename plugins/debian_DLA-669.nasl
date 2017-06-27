#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-669-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94143);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/27 15:13:33 $");

  script_cve_id("CVE-2015-8538", "CVE-2015-8750", "CVE-2016-2050", "CVE-2016-2091", "CVE-2016-5034", "CVE-2016-5036", "CVE-2016-5038", "CVE-2016-5039", "CVE-2016-5042");
  script_osvdb_id(131684, 132580, 133557, 133798, 139154, 139156, 139158, 139159, 139163);

  script_name(english:"Debian DLA-669-1 : dwarfutils security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in dwarfutils, a tool and
library for reading/consuming and writing/producing DWARF debugging
information. The Common Vulnerabilities and Exposures project
identifies the following issues :

CVE-2015-8538

A specially crafted ELF file can cause a segmentation fault.

CVE-2015-8750

A specially crafted ELF file can cause a NULL pointer dereference.

CVE-2016-2050

Out-of-bounds write

CVE-2016-2091

Out-of-bounds read

CVE-2016-5034

Out-of-bounds write

CVE-2016-5036

Out-of-bounds read

CVE-2016-5038

Out-of-bounds read

CVE-2016-5039

Out-of-bounds read

CVE-2016-5042

A specially crafted DWARF section can cause an infinite loop, reading
from increasing memory addresses until the application crashes.

For Debian 7 'Wheezy', these problems have been fixed in version
20120410-2+deb7u2.

We recommend that you upgrade your dwarfutils packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dwarfutils"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected dwarfdump, and libdwarf-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dwarfdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdwarf-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"dwarfdump", reference:"20120410-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libdwarf-dev", reference:"20120410-2+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
