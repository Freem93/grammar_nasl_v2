#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2435. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58392);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2010-4337", "CVE-2011-4328", "CVE-2012-1175");
  script_bugtraq_id(45102, 50747, 52446);
  script_osvdb_id(69533, 77243, 80156);
  script_xref(name:"DSA", value:"2435");

  script_name(english:"Debian DSA-2435-1 : gnash - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in Gnash, the GNU Flash
player.

  - CVE-2012-1175
    Tielei Wang from Georgia Tech Information Security
    Center discovered a vulnerability in GNU Gnash which is
    caused due to an integer overflow error and can be
    exploited to cause a heap-based buffer overflow by
    tricking a user into opening a specially crafted SWF
    file.

  - CVE-2011-4328
    Alexander Kurtz discovered an unsafe management of HTTP
    cookies. Cookie files are stored under /tmp and have
    predictable names, and the vulnerability allows a local
    attacker to overwrite arbitrary files the users has
    write permissions for, and are also world-readable which
    may cause information leak.

  - CVE-2010-4337
    Jakub Wilk discovered an unsafe management of temporary
    files during the build process. Files are stored under
    /tmp and have predictable names, and the vulnerability
    allows a local attacker to overwrite arbitrary files the
    users has write permissions for."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=605419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=649384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=664023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gnash"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2435"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnash packages.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.8-5+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"browser-plugin-gnash", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash-common", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash-common-opengl", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash-cygnal", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash-dbg", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash-doc", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash-opengl", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnash-tools", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"klash", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"klash-opengl", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"konqueror-plugin-gnash", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mozilla-plugin-gnash", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"swfdec-gnome", reference:"0.8.8-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"swfdec-mozilla", reference:"0.8.8-5+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
