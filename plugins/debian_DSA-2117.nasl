#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2117. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49767);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/01/27 00:45:19 $");

  script_cve_id("CVE-2010-1623");
  script_bugtraq_id(43673);
  script_xref(name:"DSA", value:"2117");

  script_name(english:"Debian DSA-2117-1 : apr-util - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"APR-util is part of the Apache Portable Runtime library which is used
by projects such as Apache httpd and Subversion.

Jeff Trawick discovered a flaw in the apr_brigade_split_line()
function in apr-util. A remote attacker could send crafted http
requests to cause a greatly increased memory consumption in Apache
httpd, resulting in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2117"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apr-util packages.

This upgrade fixes this issue. After the upgrade, any running apache2
server processes need to be restarted.

For the stable distribution (lenny), this problem has been fixed in
version 1.2.12+dfsg-8+lenny5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libaprutil1", reference:"1.2.12+dfsg-8+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1-dbg", reference:"1.2.12+dfsg-8+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1-dev", reference:"1.2.12+dfsg-8+lenny5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
