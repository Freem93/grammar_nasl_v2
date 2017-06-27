#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-661. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16266);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2005-0017", "CVE-2005-0018");
  script_osvdb_id(13231, 13232);
  script_xref(name:"DSA", value:"661");

  script_name(english:"Debian DSA-661-2 : f2c - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan McMahill noticed that our advisory DSA 661-1 did not correct the
multiple insecure files problem, hence, this update. For completeness
below is the original advisory text :

  Javier Fernandez-Sanguino Pena from the Debian Security Audit
  project discovered that f2c and fc, which are both part of the f2c
  package, a fortran 77 to C/C++ translator, open temporary files
  insecurely and are hence vulnerable to a symlink attack. The Common
  Vulnerabilities and Exposures project identifies the following
  vulnerabilities :

    - CAN-2005-0017
      Multiple insecure temporary files in the f2c
      translator.

    - CAN-2005-0018

      Two insecure temporary files in the f2 shell script."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-661"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the f2c package.

For the stable distribution (woody) and all others including testing
this problem has been fixed in version 20010821-3.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2c");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/27");
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
if (deb_check(release:"3.0", prefix:"f2c", reference:"20010821-3.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
