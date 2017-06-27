#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2880. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73065);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2013-4238", "CVE-2014-1912");
  script_bugtraq_id(61738, 65379);
  script_xref(name:"DSA", value:"2880");

  script_name(english:"Debian DSA-2880-1 : python2.7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were discovered in Python :

  - CVE-2013-4238
    Ryan Sleevi discovered that NULL characters in the
    subject alternate names of SSL cerficates were parsed
    incorrectly.

  - CVE-2014-1912
    Ryan Smith-Roberts discovered a buffer overflow in the
    socket.recvfrom_into() function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python2.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2880"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python2.7 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.7.3-6+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/18");
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
if (deb_check(release:"7.0", prefix:"idle-python2.7", reference:"2.7.3-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libpython2.7", reference:"2.7.3-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7", reference:"2.7.3-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-dbg", reference:"2.7.3-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-dev", reference:"2.7.3-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-doc", reference:"2.7.3-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-examples", reference:"2.7.3-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-minimal", reference:"2.7.3-6+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
