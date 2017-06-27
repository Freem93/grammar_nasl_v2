#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-618. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16049);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1025", "CVE-2004-1026");
  script_bugtraq_id(11830);
  script_osvdb_id(12843);
  script_xref(name:"DSA", value:"618");

  script_name(english:"Debian DSA-618-1 : imlib - buffer overflows, integer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Pavel Kankovsky discovered that several overflows found in the libXpm
library were also present in imlib, an imaging library for X and X11.
An attacker could create a carefully crafted image file in such a way
that it could cause an application linked with imlib to execute
arbitrary code when the file was opened by a victim. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CAN-2004-1025
    Multiple heap-based buffer overflows.

  - CAN-2004-1026

    Multiple integer overflows."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=284925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-618"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imlib packages immediately.

For the stable distribution (woody) these problems have been fixed in
version 1.9.14-2woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"gdk-imlib-dev", reference:"1.9.14-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"gdk-imlib1", reference:"1.9.14-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"imlib-base", reference:"1.9.14-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"imlib-dev", reference:"1.9.14-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"imlib-progs", reference:"1.9.14-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"imlib1", reference:"1.9.14-2woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
