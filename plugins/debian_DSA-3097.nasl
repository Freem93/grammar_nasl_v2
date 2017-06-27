#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3097. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79884);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-8602");
  script_bugtraq_id(71589);
  script_osvdb_id(115667);
  script_xref(name:"DSA", value:"3097");

  script_name(english:"Debian DSA-3097-1 : unbound - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Maury from ANSSI discovered that unbound, a validating,
recursive, and caching DNS resolver, was prone to a denial of service
vulnerability. An attacker crafting a malicious zone and able to emit
(or make emit) queries to the server can trick the resolver into
following an endless series of delegations, leading to resource
exhaustion and huge network usage."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=772622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/unbound"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3097"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the unbound packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4.17-3+deb7u2.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 1.4.22-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (deb_check(release:"7.0", prefix:"libunbound-dev", reference:"1.4.17-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libunbound2", reference:"1.4.17-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-unbound", reference:"1.4.17-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"unbound", reference:"1.4.17-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"unbound-anchor", reference:"1.4.17-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"unbound-host", reference:"1.4.17-3+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
