#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1152. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22694);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-3695");
  script_osvdb_id(27082, 27083);
  script_xref(name:"DSA", value:"1152");

  script_name(english:"Debian DSA-1152-1 : trac - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Felix Wiemann discovered that trac, an enhanced Wiki and issue
tracking system for software development projects, can be used to
disclose arbitrary local files. To fix this problem, python-docutils
needs to be updated as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1152"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the trac and python-docutils packages.

For the stable distribution (sarge) this problem has been fixed in
version 0.8.1-3sarge5 of trac and version 0.3.7-2sarge1 of
python-docutils."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trac");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"python-docutils", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python-roman", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-difflib", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-textwrap", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.2-docutils", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.2-textwrap", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-docutils", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.4-docutils", reference:"0.3.7-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"trac", reference:"0.8.1-3sarge5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
