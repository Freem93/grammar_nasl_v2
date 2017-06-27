#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3115. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80286);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 18:23:49 $");

  script_cve_id("CVE-2014-9130");
  script_bugtraq_id(71349);
  script_osvdb_id(115190);
  script_xref(name:"DSA", value:"3115");

  script_name(english:"Debian DSA-3115-1 : pyyaml - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jonathan Gray and Stanislaw Pitucha found an assertion failure in the
way wrapped strings are parsed in Python-YAML, a YAML parser and
emitter for Python. An attacker able to load specially crafted YAML
input into an application using python-yaml could cause the
application to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=772815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/pyyaml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3115"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pyyaml packages.

For the stable distribution (wheezy), this problem has been fixed in
version 3.10-4+deb7u1.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 3.11-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pyyaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");
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
if (deb_check(release:"7.0", prefix:"python-yaml", reference:"3.10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-yaml-dbg", reference:"3.10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3-yaml", reference:"3.10-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3-yaml-dbg", reference:"3.10-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
