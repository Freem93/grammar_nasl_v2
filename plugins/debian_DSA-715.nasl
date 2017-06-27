#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-715. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18151);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2004-1342", "CVE-2004-1343");
  script_osvdb_id(15887, 15888);
  script_xref(name:"CERT", value:"327037");
  script_xref(name:"DSA", value:"715");

  script_name(english:"Debian DSA-715-1 : cvs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in the CVS server, which serves
the popular Concurrent Versions System. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CAN-2004-1342
    Maks Polunin and Alberto Garcia discovered independently
    that using the pserver access method in connection with
    the repouid patch that Debian uses it is possible to
    bypass the password and gain access to the repository in
    question.

  - CAN-2004-1343

    Alberto Garcia discovered that a remote user can cause
    the cvs server to crash when the cvs-repouids file
    exists but does not contain a mapping for the current
    repository, which can be used as a denial of service
    attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=260200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-715"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cvs package.

For the stable distribution (woody) these problems have been fixed in
version 1.11.1p1debian-10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"cvs", reference:"1.11.1p1debian-10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
