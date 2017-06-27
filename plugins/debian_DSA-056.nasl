#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-056. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14893);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-1331");
  script_bugtraq_id(2720);
  script_xref(name:"DSA", value:"056");

  script_name(english:"Debian DSA-056-1 : man-db - local file overwrite");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ethan Benson found a bug in man-db packages as distributed in Debian
 GNU/Linux 2.2. man-db includes a mandb tool which is used to build an
 index of the manual pages installed on a system. When the -u or -c
 option were given on the command-line to tell it to write its
 database to a different location it failed to properly drop
 privileges before creating a temporary file. This makes it possible
 for an attacker to do a standard symlink attack to trick mandb into
 overwriting any file that is writable by uid man, which includes the
 man and mandb binaries."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-056"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in version 2.3.16-3, and we recommend that you
upgrade your man-db package immediately. If you use suidmanager you
can also use that to make sure man and mandb are not installed suid
which protects you from this problem. This can be done with the
following commands: suidregister /usr/lib/man-db/man root root 0755
suidregister /usr/lib/man-db/mandb root root 0755

Of course even when using suidmanager an upgrade is still strongly
recommended."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:man-db");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/05/08");
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
if (deb_check(release:"2.2", prefix:"man-db", reference:"2.3.16-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
