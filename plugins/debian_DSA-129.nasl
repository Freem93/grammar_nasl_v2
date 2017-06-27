#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-129. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14966);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:41:27 $");

  script_cve_id("CVE-2002-0912");
  script_bugtraq_id(4910);
  script_osvdb_id(14455);
  script_xref(name:"DSA", value:"129");

  script_name(english:"Debian DSA-129-1 : uucp - remote denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"We have received reports that in.uucpd, an authentication agent in the
uucp package, does not properly terminate certain long input strings.
This has been corrected in uucp package version 1.06.1-11potato3 for
Debian 2.2 (potato) and in version 1.06.1-18 for the upcoming (woody)
release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-129"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the uucp package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uucp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/27");
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
if (deb_check(release:"2.2", prefix:"uucp", reference:"1.06.1-11potato3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
