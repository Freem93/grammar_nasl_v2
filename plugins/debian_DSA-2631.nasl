#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2631. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64867);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/15 14:21:39 $");

  script_cve_id("CVE-2012-5643", "CVE-2013-0189");
  script_osvdb_id(88492);
  script_xref(name:"DSA", value:"2631");

  script_name(english:"Debian DSA-2631-1 : squid3 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Squid3, a fully featured Web proxy cache, is prone to a denial of
service attack due to memory consumption caused by memory leaks in
cachemgr.cgi :

  - CVE-2012-5643
    squid's cachemgr.cgi was vulnerable to excessive
    resource use. A remote attacker could exploit this flaw
    to perform a denial of service attack on the server and
    other hosted services.

  - CVE-2013-0189
    The original patch for CVE-2012-5643 was incomplete. A
    remote attacker still could exploit this flaw to perform
    a denial of service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=696187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2631"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid3 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 3.1.6-1.2+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"squid-cgi", reference:"3.1.6-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"squid3", reference:"3.1.6-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"squid3-common", reference:"3.1.6-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"squid3-dbg", reference:"3.1.6-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"squidclient", reference:"3.1.6-1.2+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
