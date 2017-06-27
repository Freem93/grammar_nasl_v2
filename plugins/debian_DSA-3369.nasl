#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3369. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86303);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/10 14:05:03 $");

  script_cve_id("CVE-2015-5723", "CVE-2015-7695");
  script_xref(name:"DSA", value:"3369");

  script_name(english:"Debian DSA-3369-1 : zendframework - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in Zend Framework, a PHP
framework :

  - CVE-2015-5723
    It was discovered that due to incorrect permissions
    masks when creating directories, local attackers could
    potentially execute arbitrary code or escalate
    privileges.

  - ZF2015-08 (no CVE assigned)

    Chris Kings-Lynne discovered a SQL injection vector
    caused by missing null byte filtering in the MS SQL PDO
    backend, and a similar issue was also found in the
    SQLite backend."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/zendframework"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/zendframework"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3369"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the zendframework packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.11.13-1.1+deb7u4.

For the stable distribution (jessie), this problem has been fixed in
version 1.12.9+dfsg-2+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zendframework");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/07");
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
if (deb_check(release:"7.0", prefix:"zendframework", reference:"1.11.13-1.1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"zendframework-bin", reference:"1.11.13-1.1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"zendframework-resources", reference:"1.11.13-1.1+deb7u4")) flag++;
if (deb_check(release:"8.0", prefix:"zendframework", reference:"1.12.9+dfsg-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"zendframework-bin", reference:"1.12.9+dfsg-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"zendframework-resources", reference:"1.12.9+dfsg-2+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
