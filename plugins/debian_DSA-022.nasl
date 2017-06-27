#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-022. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14859);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0125");
  script_bugtraq_id(2201);
  script_xref(name:"DSA", value:"022");

  script_name(english:"Debian DSA-022-1 : exmh - local insecure tempfile creation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Former versions of the exmh program used /tmp for storing temporary
files. No checks were made to ensure that nobody placed a symlink with
the same name in /tmp in the meantime and thus was vulnerable to a
symlink attack. This could lead to a malicious local user being able
to overwrite any file writable by the user executing exmh. Upstream
developers have reported and fixed this. The exmh program now use
/tmp/login unless TMPDIR or EXMHTMPDIR is set."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-022"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the exmh packages immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exmh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"exmh", reference:"2.1.1-1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
