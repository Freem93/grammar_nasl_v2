#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2176. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52484);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/20 15:05:35 $");

  script_cve_id("CVE-2008-5183", "CVE-2009-3553", "CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748", "CVE-2010-2431", "CVE-2010-2432", "CVE-2010-2941");
  script_bugtraq_id(32419, 37048, 40889, 40897, 40943, 41126, 41131, 44530);
  script_osvdb_id(50351, 60204, 65555, 65569, 65692, 65698, 65699, 68951);
  script_xref(name:"DSA", value:"2176");

  script_name(english:"Debian DSA-2176-1 : cups - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Common UNIX
Printing System :

  - CVE-2008-5183
    A NULL pointer dereference in RSS job completion
    notifications could lead to denial of service.

  - CVE-2009-3553
    It was discovered that incorrect file descriptor
    handling could lead to denial of service.

  - CVE-2010-0540
    A cross-site request forgery vulnerability was
    discovered in the web interface.

  - CVE-2010-0542
    Incorrect memory management in the filter subsystem
    could lead to denial of service.

  - CVE-2010-1748
    Information disclosure in the web interface.

  - CVE-2010-2431
    Emmanuel Bouillon discovered a symlink vulnerability in
    handling of cache files.

  - CVE-2010-2432
    Denial of service in the authentication code.

  - CVE-2010-2941
    Incorrect memory management in the IPP code could lead
    to denial of service or the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2176"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.8-1+lenny9.

The stable distribution (squeeze) and the unstable distribution (sid)
had already been fixed prior to the initial Squeeze release."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"cups", reference:"1.3.8-1+lenny9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
