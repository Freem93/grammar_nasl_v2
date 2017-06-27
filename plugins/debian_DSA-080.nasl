#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-080. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14917);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0834");
  script_osvdb_id(654, 7591);
  script_xref(name:"DSA", value:"080");

  script_name(english:"Debian DSA-080-1 : htdig - unauthorized gathering of data");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nergal reported a vulnerability in the htsearch program which is
 distributed as part of the ht://Dig package, an indexing and
 searching system for small domains or intranets. Using former
 versions it was able to pass the parameter -c to the cgi program in
 order to use a different configuration file.

A malicious user could point htsearch to a file like/dev/zero and let
the server run in an endless loop, trying to read config parameters.
If the user has write permission on the server they can point the
program to it and retrieve any file readable by the webserver user id."
  );
  # http://sourceforge.net/tracker/index.php?func=detail&aid=458013&group_id=4593&atid=104593
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8db54e57"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-080"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the htdig package immediately.

This problem has been fixed in version 3.1.5-2.0potato.1 for Debian
GNU/Linux 2.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:htdig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"htdig", reference:"3.1.5-2.0potato.1")) flag++;
if (deb_check(release:"2.2", prefix:"htdig-doc", reference:"3.1.5-2.0potato.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
