#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1242. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23947);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2006-5063", "CVE-2006-5790", "CVE-2006-5791", "CVE-2006-6318");
  script_osvdb_id(29120, 30175, 30176, 30177, 30272);
  script_xref(name:"DSA", value:"1242");

  script_name(english:"Debian DSA-1242-1 : elog - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in elog, a
web-based electronic logbook, which may lead to the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2006-5063
    Tilman Koschnick discovered that log entry editing in
    HTML is vulnerable to cross-site scripting. This update
    disables the vulnerable code.

  - CVE-2006-5790
    Ulf Harnhammar of the Debian Security Audit Project
    discovered several format string vulnerabilities in
    elog, which may lead to execution of arbitrary code.

  - CVE-2006-5791
    Ulf Harnhammar of the Debian Security Audit Project
    discovered cross-site scripting vulnerabilities in the
    creation of new logbook entries.

  - CVE-2006-6318
    Jayesh KS and Arun Kethipelly of OS2A discovered that
    elog performs insufficient error handling in config file
    parsing, which may lead to denial of service through a
    NULL pointer dereference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1242"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the elog package.

For the stable distribution (sarge) these problems have been fixed in
version 2.5.7+r1558-4+sarge3.

The upcoming stable distribution (etch) will no longer include elog."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:elog");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"elog", reference:"2.5.7+r1558-4+sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
