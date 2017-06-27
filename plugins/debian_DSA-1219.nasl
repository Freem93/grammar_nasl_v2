#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1219. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23742);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2005-3011", "CVE-2006-4810");
  script_bugtraq_id(14854, 20959);
  script_osvdb_id(19409, 30245, 30246);
  script_xref(name:"DSA", value:"1219");

  script_name(english:"Debian DSA-1219-1 : texinfo - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in the GNU texinfo package, a
documentation system for on-line information and printed output.

  - CVE-2005-3011
    Handling of temporary files is performed in an insecure
    manner, allowing an attacker to overwrite any file
    writable by the victim.

  - CVE-2006-4810
    A buffer overflow in util/texindex.c could allow an
    attacker to execute arbitrary code with the victim's
    access rights by inducing the victim to run texindex or
    tex2dvi on a specially crafted texinfo file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1219"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the texinfo package.

For the stable distribution (sarge), these problems have been fixed in
version 4.7-2.2sarge2. Note that binary packages for the mipsel
architecture are not currently available due to technical problems
with the build host. These packages will be made available as soon as
possible.

For unstable (sid) and the upcoming stable release (etch), these
problems have been fixed in version 4.8.dfsg.1-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/14");
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
if (deb_check(release:"3.1", prefix:"info", reference:"4.7-2.2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"texinfo", reference:"4.7-2.2sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
