#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1980. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44844);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2009-4016", "CVE-2010-0300");
  script_osvdb_id(62150, 62151, 62152, 62153);
  script_xref(name:"DSA", value:"1980");

  script_name(english:"Debian DSA-1980-1 : ircd-hybrid/ircd-ratbox - integer underflow/denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"David Leadbeater discovered an integer underflow that could be
triggered via the LINKS command and can lead to a denial of service or
the execution of arbitrary code (CVE-2009-4016 ). This issue affects
both, ircd-hybrid and ircd-ratbox.

It was discovered that the ratbox IRC server is prone to a denial of
service attack via the HELP command. The ircd-hybrid package is not
vulnerable to this issue (CVE-2010-0300 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1980"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ircd-hybrid/ircd-ratbox packages.

For the stable distribution (lenny), this problem has been fixed in
version 1:7.2.2.dfsg.2-4+lenny1 of the ircd-hybrid package and in
version 2.2.8.dfsg-2+lenny1 of ircd-ratbox.

Due to a bug in the archive software it was not possible to release
the fix for the oldstable distribution (etch) simultaneously. The
packages will be released as version 7.2.2.dfsg.2-3+etch1 once they
become available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ircd-ratbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"hybrid-dev", reference:"1:7.2.2.dfsg.2-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ircd-hybrid", reference:"1:7.2.2.dfsg.2-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ircd-ratbox", reference:"1:2.2.8.dfsg-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ircd-ratbox-dbg", reference:"1:2.2.8.dfsg-2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
