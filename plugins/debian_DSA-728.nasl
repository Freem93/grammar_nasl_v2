#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-728. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18515);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1151", "CVE-2005-1152");
  script_osvdb_id(16811);
  script_xref(name:"DSA", value:"728");

  script_name(english:"Debian DSA-728-2 : qpopper - missing privilege release");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This advisory does only cover updated packages for Debian 3.0 alias
woody. For reference below is the original advisory text :

  Two bugs have been discovered in qpopper, an enhanced Post Office
  Protocol (POP3) server. The Common Vulnerabilities and Exposures
  project identifies the following problems :

    - CAN-2005-1151
      Jens Steube discovered that while processing local
      files owned or provided by a normal user privileges
      weren't dropped, which could lead to the overwriting
      or creation of arbitrary files as root.

    - CAN-2005-1152

      The upstream developers noticed that qpopper could be
      tricked to creating group- or world-writable files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-728"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qpopper package.

For the stable distribution (woody) these problems have been fixed in
version 4.0.4-2.woody.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qpopper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/23");
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
if (deb_check(release:"3.0", prefix:"qpopper", reference:"4.0.4-2.woody.5")) flag++;
if (deb_check(release:"3.0", prefix:"qpopper-drac", reference:"4.0.4-2.woody.5")) flag++;
if (deb_check(release:"3.1", prefix:"qpopper", reference:"4.0.5-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qpopper-drac", reference:"4.0.5-4sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
