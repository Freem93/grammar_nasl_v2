#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-942. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22808);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/06 11:35:45 $");

  script_cve_id("CVE-2006-0044");
  script_bugtraq_id(16252);
  script_osvdb_id(22451);
  script_xref(name:"DSA", value:"942");

  script_name(english:"Debian DSA-942-1 : albatross - design error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A design error has been discovered in the Albatross web application
toolkit that causes user-supplied data to be used as part of template
execution and hence arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-942"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the albatross package.

The old stable distribution (woody) does not contain albatross
packages.

For the stable distribution (sarge) this problem has been fixed in
version 1.20-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:albatross");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"python-albatross", reference:"1.20-2")) flag++;
if (deb_check(release:"3.1", prefix:"python-albatross-common", reference:"1.20-2")) flag++;
if (deb_check(release:"3.1", prefix:"python-albatross-doc", reference:"1.20-2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.2-albatross", reference:"1.20-2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-albatross", reference:"1.20-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
