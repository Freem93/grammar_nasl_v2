#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2652. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65695);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-0338", "CVE-2013-0339");
  script_bugtraq_id(58180);
  script_osvdb_id(90630, 90631);
  script_xref(name:"DSA", value:"2652");

  script_name(english:"Debian DSA-2652-1 : libxml2 - external entity expansion");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brad Hill of iSEC Partners discovered that many XML implementations
are vulnerable to external entity expansion issues, which can be used
for various purposes such as firewall circumvention, disguising an IP
address, and denial-of-service. libxml2 was susceptible to these
problems when performing string substitution during entity expansion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2652"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.7.8.dfsg-2+squeeze7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");
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
if (deb_check(release:"6.0", prefix:"libxml2", reference:"2.7.8.dfsg-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-dev", reference:"2.7.8.dfsg-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-doc", reference:"2.7.8.dfsg-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libxml2-utils", reference:"2.7.8.dfsg-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2", reference:"2.7.8.dfsg-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxml2-dbg", reference:"2.7.8.dfsg-2+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
