#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3048. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78092);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2014-7206");
  script_bugtraq_id(70310);
  script_xref(name:"DSA", value:"3048");

  script_name(english:"Debian DSA-3048-1 : apt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Guillem Jover discovered that the changelog retrieval functionality in
apt-get used temporary files in an insecure way, allowing a local user
to cause arbitrary files to be overwritten.

This vulnerability is neutralized by the fs.protected_symlinks setting
in the Linux kernel, which is enabled by default in Debian 7 Wheezy
and up."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=763780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3048"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apt packages.

For the stable distribution (wheezy), this problem has been fixed in
version 0.9.7.9+deb7u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/09");
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
if (deb_check(release:"7.0", prefix:"apt", reference:"0.9.7.9+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"apt-doc", reference:"0.9.7.9+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"apt-transport-https", reference:"0.9.7.9+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"apt-utils", reference:"0.9.7.9+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-inst1.5", reference:"0.9.7.9+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg-dev", reference:"0.9.7.9+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg-doc", reference:"0.9.7.9+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg4.12", reference:"0.9.7.9+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
