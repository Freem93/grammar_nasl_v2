#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3228. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82864);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/14 13:43:55 $");

  script_cve_id("CVE-2015-3310");
  script_bugtraq_id(74163);
  script_osvdb_id(120609);
  script_xref(name:"DSA", value:"3228");

  script_name(english:"Debian DSA-3228-1 : ppp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Emanuele Rocca discovered that ppp, a daemon implementing the
Point-to-Point Protocol, was subject to a buffer overflow when
communicating with a RADIUS server. This would allow unauthenticated
users to cause a denial-of-service by crashing the daemon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ppp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3228"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ppp packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.4.5-5.1+deb7u2.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 2.4.6-3.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ppp", reference:"2.4.5-5.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ppp-dev", reference:"2.4.5-5.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ppp-udeb", reference:"2.4.5-5.1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
