#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1734. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35790);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-0368");
  script_bugtraq_id(33922);
  script_xref(name:"DSA", value:"1734");

  script_name(english:"Debian DSA-1734-1 : opensc - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"b.badrignans discovered that OpenSC, a set of smart card utilities,
could stores private data on a smart card without proper access
restrictions.

Only blank cards initialised with OpenSC are affected by this problem.
This update only improves creating new private data objects, but cards
already initialised with such private data objects need to be modified
to repair the access control conditions on such cards. Instructions
for a variety of situations can be found at the OpenSC website:
http://www.opensc-project.org/security.html

The oldstable distribution (etch) is not affected by this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1734"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the opensc package and recreate any private data objects
stored on the smart cards.

For the stable distribution (lenny), this problem has been fixed in
version 0.11.4-5+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libopensc2", reference:"0.11.4-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libopensc2-dbg", reference:"0.11.4-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libopensc2-dev", reference:"0.11.4-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mozilla-opensc", reference:"0.11.4-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"opensc", reference:"0.11.4-5+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
