#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3830. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99484);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/04/26 13:35:46 $");

  script_cve_id("CVE-2017-7867", "CVE-2017-7868");
  script_osvdb_id(152114);
  script_xref(name:"DSA", value:"3830");

  script_name(english:"Debian DSA-3830-1 : icu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that icu, the International Components for Unicode
library, did not correctly validate its input. An attacker could use
this problem to trigger an out-of-bound write through a heap-based
buffer overflow, thus causing a denial of service via application
crash, or potential execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=860314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3830"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icu packages.

For the stable distribution (jessie), these problems have been fixed
in version 52.1-8+deb8u5.

For the upcoming stable (stretch) and unstable (sid) distributions,
these problems have been fixed in version 57.1-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"icu-devtools", reference:"52.1-8+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"icu-doc", reference:"52.1-8+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libicu-dev", reference:"52.1-8+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libicu52", reference:"52.1-8+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libicu52-dbg", reference:"52.1-8+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
