#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2815. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71278);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6048", "CVE-2013-6359");
  script_osvdb_id(100733, 100734);
  script_xref(name:"DSA", value:"2815");

  script_name(english:"Debian DSA-2815-1 : munin - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christoph Biedl discovered two denial of service vulnerabilities in
munin, a network-wide graphing framework. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2013-6048
    The Munin::Master::Node module of munin does not
    properly validate certain data a node sends. A malicious
    node might exploit this to drive the munin-html process
    into an infinite loop with memory exhaustion on the
    munin master.

  - CVE-2013-6359
    A malicious node, with a plugin enabled using
    'multigraph' as a multigraph service name, can abort
    data collection for the entire node the plugin runs on."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/munin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2815"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the munin packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.0.6-4+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (deb_check(release:"7.0", prefix:"munin", reference:"2.0.6-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"munin-async", reference:"2.0.6-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"munin-common", reference:"2.0.6-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"munin-doc", reference:"2.0.6-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"munin-node", reference:"2.0.6-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"munin-plugins-core", reference:"2.0.6-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"munin-plugins-extra", reference:"2.0.6-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"munin-plugins-java", reference:"2.0.6-4+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
