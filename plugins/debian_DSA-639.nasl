#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-639. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(16165);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1009", "CVE-2004-1090", "CVE-2004-1091", "CVE-2004-1092", "CVE-2004-1093", "CVE-2004-1174", "CVE-2004-1175", "CVE-2004-1176");
  script_osvdb_id(12902, 12903, 12904, 12905, 12906, 12907, 12908, 12909, 12910, 12911);
  script_xref(name:"DSA", value:"639");

  script_name(english:"Debian DSA-639-1 : mc - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrew V. Samoilov has noticed that several bugfixes which were
applied to the source by upstream developers of mc, the midnight
commander, a file browser and manager, were not backported to the
current version of mc that Debian ships in their stable release. The
Common Vulnerabilities and Exposures Project identifies the following
vulnerabilities :

  - CAN-2004-1004
    Multiple format string vulnerabilities

  - CAN-2004-1005

    Multiple buffer overflows

  - CAN-2004-1009

    One infinite loop vulnerability

  - CAN-2004-1090

    Denial of service via corrupted section header

  - CAN-2004-1091

    Denial of service via null dereference

  - CAN-2004-1092

    Freeing unallocated memory

  - CAN-2004-1093

    Denial of service via use of already freed memory

  - CAN-2004-1174

    Denial of service via manipulating non-existing file
    handles

  - CAN-2004-1175

    Unintended program execution via insecure filename
    quoting

  - CAN-2004-1176

    Denial of service via a buffer underflow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-639"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mc package.

For the stable distribution (woody) these problems have been fixed in
version 4.5.55-1.2woody5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"gmc", reference:"4.5.55-1.2woody5")) flag++;
if (deb_check(release:"3.0", prefix:"mc", reference:"4.5.55-1.2woody5")) flag++;
if (deb_check(release:"3.0", prefix:"mc-common", reference:"4.5.55-1.2woody5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
