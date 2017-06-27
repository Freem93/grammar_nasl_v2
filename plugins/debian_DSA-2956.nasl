#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2956. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74477);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/10 14:05:03 $");

  script_cve_id("CVE-2013-7106", "CVE-2013-7107", "CVE-2013-7108", "CVE-2014-1878", "CVE-2014-2386");
  script_bugtraq_id(64363, 64370, 64374, 65605, 66212);
  script_osvdb_id(101032, 101319, 101320, 101321, 101322, 101323, 101324, 101325, 101336, 101337, 101338, 103453);
  script_xref(name:"DSA", value:"2956");

  script_name(english:"Debian DSA-2956-1 : icinga - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in the Icinga host and
network monitoring system (buffer overflows, cross-site request
forgery, off-by ones) which could result in the execution of arbitrary
code, denial of service or session hijacking."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icinga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2956"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icinga packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.7.1-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"icinga", reference:"1.7.1-7")) flag++;
if (deb_check(release:"7.0", prefix:"icinga-cgi", reference:"1.7.1-7")) flag++;
if (deb_check(release:"7.0", prefix:"icinga-common", reference:"1.7.1-7")) flag++;
if (deb_check(release:"7.0", prefix:"icinga-core", reference:"1.7.1-7")) flag++;
if (deb_check(release:"7.0", prefix:"icinga-dbg", reference:"1.7.1-7")) flag++;
if (deb_check(release:"7.0", prefix:"icinga-doc", reference:"1.7.1-7")) flag++;
if (deb_check(release:"7.0", prefix:"icinga-idoutils", reference:"1.7.1-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
