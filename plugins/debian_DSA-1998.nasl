#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1998. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44862);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/05 14:32:00 $");

  script_cve_id("CVE-2009-0689");
  script_bugtraq_id(35510);
  script_osvdb_id(55603, 61091, 61186, 61187, 61188, 61189, 62402);
  script_xref(name:"DSA", value:"1998");

  script_name(english:"Debian DSA-1998-1 : kdelibs - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Maksymilian Arciemowicz discovered a buffer overflow in the internal
string routines of the KDE core libraries, which could lead to the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1998"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdelibs packages.

For the stable distribution (lenny), this problem has been fixed in
version 4:3.5.10.dfsg.1-0lenny4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/17");
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
if (deb_check(release:"5.0", prefix:"kdelibs", reference:"4:3.5.10.dfsg.1-0lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs-data", reference:"4:3.5.10.dfsg.1-0lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs-dbg", reference:"4:3.5.10.dfsg.1-0lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs4-dev", reference:"4:3.5.10.dfsg.1-0lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs4-doc", reference:"4:3.5.10.dfsg.1-0lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"kdelibs4c2a", reference:"4:3.5.10.dfsg.1-0lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
