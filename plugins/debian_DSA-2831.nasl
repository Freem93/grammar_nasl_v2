#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2831. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71779);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-4969");
  script_bugtraq_id(64552);
  script_osvdb_id(101432);
  script_xref(name:"DSA", value:"2831");

  script_name(english:"Debian DSA-2831-1 : puppet - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An unsafe use of temporary files was discovered in Puppet, a tool for
centralized configuration management. An attacker can exploit this
vulnerability and overwrite an arbitrary file in the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/puppet"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/puppet"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2831"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the puppet packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 2.6.2-5+squeeze9.

For the stable distribution (wheezy), this problem has been fixed in
version 2.7.23-1~deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"puppet", reference:"2.6.2-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-common", reference:"2.6.2-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-el", reference:"2.6.2-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-testsuite", reference:"2.6.2-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"puppetmaster", reference:"2.6.2-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"vim-puppet", reference:"2.6.2-5+squeeze9")) flag++;
if (deb_check(release:"7.0", prefix:"puppet", reference:"2.7.23-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-common", reference:"2.7.23-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-el", reference:"2.7.23-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-testsuite", reference:"2.7.23-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster", reference:"2.7.23-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster-common", reference:"2.7.23-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster-passenger", reference:"2.7.23-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vim-puppet", reference:"2.7.23-1~deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
