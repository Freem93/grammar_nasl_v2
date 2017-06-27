#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-073. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14910);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/11/05 11:41:02 $");

  script_cve_id("CVE-2001-1257", "CVE-2001-1258", "CVE-2001-1370");
  script_bugtraq_id(3082, 3083);
  script_osvdb_id(9290);
  script_xref(name:"DSA", value:"073");

  script_name(english:"Debian DSA-073-1 : imp - 3 remote exploits");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Horde team released version 2.2.6 of IMP (a web-based IMAP mail
 program) which fixes three security problems. Their release
 announcement describes them as follows :

  - A PHPLIB vulnerability allowed an attacker to provide a
    value for the array element $_PHPLIB[libdir], and thus
    to get scripts from another server to load and execute.
    This vulnerability is remotely exploitable. (Horde 1.2.x
    ships with its own customized version of PHPLIB, which
    has now been patched to prevent this problem.)
  - By using tricky encodings of 'javascript:' an attacker
    can cause malicious JavaScript code to execute in the
    browser of a user reading email sent by attacker. (IMP
    2.2.x already filters many such patterns; several new
    ones that were slipping past the filters are now
    blocked.)

  - A hostile user that can create a publicly-readable file
    named 'prefs.lang' somewhere on the Apache/PHP server
    can cause that file to be executed as PHP code. The IMP
    configuration files could thus be read, the Horde
    database password used to read and alter the database
    used to store contacts and preferences, etc. We do not
    believe this is remotely exploitable directly through
    Apache/PHP/IMP; however, shell access to the server or
    other means (e.g., FTP) could be used to create this
    file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-073"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in version 2:2.2.6-0.potato.1. Please note that
you will also need to upgrade the horde package to the same version."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/21");
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
if (deb_check(release:"2.2", prefix:"horde", reference:"1.2.6-0.potato.1")) flag++;
if (deb_check(release:"2.2", prefix:"imp", reference:"2.2.6-0.potato.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
