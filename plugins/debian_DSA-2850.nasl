#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2850. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72240);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6393");
  script_bugtraq_id(65258);
  script_osvdb_id(102716);
  script_xref(name:"DSA", value:"2850");

  script_name(english:"Debian DSA-2850-1 : libyaml - heap-based buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Weimer of the Red Hat Product Security Team discovered a
heap-based buffer overflow flaw in LibYAML, a fast YAML 1.1 parser and
emitter library. A remote attacker could provide a YAML document with
a specially crafted tag that, when parsed by an application using
libyaml, would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=737076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libyaml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libyaml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2850"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libyaml packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 0.1.3-1+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in
version 0.1.4-2+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libyaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/02");
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
if (deb_check(release:"6.0", prefix:"libyaml-0-2", reference:"0.1.3-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libyaml-dev", reference:"0.1.3-1+deb6u2")) flag++;
if (deb_check(release:"7.0", prefix:"libyaml-0-2", reference:"0.1.4-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libyaml-0-2-dbg", reference:"0.1.4-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libyaml-dev", reference:"0.1.4-2+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
