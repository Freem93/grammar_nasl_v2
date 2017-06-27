#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3278. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83980);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/06/05 13:37:41 $");

  script_cve_id("CVE-2014-8111");
  script_bugtraq_id(74265);
  script_xref(name:"DSA", value:"3278");

  script_name(english:"Debian DSA-3278-1 : libapache-mod-jk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information disclosure flaw due to incorrect JkMount/JkUnmount
directives processing was found in the Apache 2 module mod_jk to
forward requests from the Apache web server to Tomcat. A JkUnmount
rule for a subtree of a previous JkMount rule could be ignored. This
could allow a remote attacker to potentially access a private artifact
in a tree that would otherwise not be accessible to them."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=783233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libapache-mod-jk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libapache-mod-jk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3278"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libapache-mod-jk packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1:1.2.37-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1:1.2.37-4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-mod-jk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/04");
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
if (deb_check(release:"7.0", prefix:"libapache-mod-jk-doc", reference:"1:1.2.37-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-jk", reference:"1:1.2.37-1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache-mod-jk-doc", reference:"1:1.2.37-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-jk", reference:"1:1.2.37-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
