#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-654. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16238);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");
  script_osvdb_id(13154, 13155, 13156);
  script_xref(name:"DSA", value:"654");

  script_name(english:"Debian DSA-654-1 : enscript - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Erik Sjolund has discovered several security relevant problems in
enscript, a program to convert ASCII text into Postscript and other
formats. The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities :

  - CAN-2004-1184
    Unsanitised input can cause the execution of arbitrary
    commands via EPSF pipe support. This has been disabled,
    also upstream.

  - CAN-2004-1185

    Due to missing sanitising of filenames it is possible
    that a specially crafted filename can cause arbitrary
    commands to be executed.

  - CAN-2004-1186

    Multiple buffer overflows can cause the program to
    crash.

Usually, enscript is only run locally, but since it is executed inside
of viewcvs some of the problems mentioned above can easily be turned
into a remote vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-654"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the enscript package.

For the stable distribution (woody) these problems have been fixed in
version 1.6.3-1.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:enscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"enscript", reference:"1.6.3-1.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
