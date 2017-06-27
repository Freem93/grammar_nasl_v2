#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1201. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22931);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-4574", "CVE-2006-4805");
  script_osvdb_id(30068, 30069, 30070, 30071, 30072, 30073);
  script_xref(name:"DSA", value:"1201");

  script_name(english:"Debian DSA-1201-1 : ethereal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Ethereal
network scanner. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2005-4574
    It was discovered that the MIME multipart dissector is
    vulnerable to denial of service caused by an off-by-one
    overflow.

  - CVE-2006-4805
    It was discovered that the XOT dissector is vulnerable
    to denial of service caused by memory corruption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=396258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1201"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ethereal packages.

For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge9. Due to technical problems with the security
buildd infrastructure this update lacks builds for the hppa and sparc
architecture. They will be released as soon as the problems are
resolved."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"ethereal", reference:"0.10.10-2sarge9")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-common", reference:"0.10.10-2sarge9")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-dev", reference:"0.10.10-2sarge9")) flag++;
if (deb_check(release:"3.1", prefix:"tethereal", reference:"0.10.10-2sarge9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
