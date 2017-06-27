#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2768. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70303);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2012-4540");
  script_bugtraq_id(62426);
  script_osvdb_id(87249);
  script_xref(name:"DSA", value:"2768");

  script_name(english:"Debian DSA-2768-1 : icedtea-web - heap-based buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow vulnerability was found in icedtea-web, a
web browser plugin for running applets written in the Java programming
language. If a user were tricked into opening a malicious website, an
attacker could cause the plugin to crash or possibly execute arbitrary
code as the user invoking the program.

This problem was initially discovered by Arthur Gerkis and got
assigned CVE-2012-4540. Fixes where applied in the 1.1, 1.2 and 1.3
branches but not to the 1.4 branch."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=723118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icedtea-web"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2768"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedtea-web packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4-3~deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"icedtea-6-plugin", reference:"1.4-3~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-7-plugin", reference:"1.4-3~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-netx", reference:"1.4-3~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-netx-common", reference:"1.4-3~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-plugin", reference:"1.4-3~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea6-plugin", reference:"1.4-3~deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
