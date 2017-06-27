#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1629. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33934);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2008-2936");
  script_bugtraq_id(30691);
  script_osvdb_id(47658);
  script_xref(name:"DSA", value:"1629");

  script_name(english:"Debian DSA-1629-2 : postfix - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sebastian Krahmer discovered that Postfix, a mail transfer agent,
incorrectly checks the ownership of a mailbox. In some configurations,
this allows for appending data to arbitrary files as root.

Note that only specific configurations are vulnerable; the default
Debian installation is not affected. Only a configuration meeting the
following requirements is vulnerable :

  - The mail delivery style is mailbox, with the Postfix
    built-in local(8) or virtual(8) delivery agents.
  - The mail spool directory (/var/spool/mail) is
    user-writeable.

  - The user can create hardlinks pointing to root-owned
    symlinks located in other directories.

For a detailed treating of the issue, please refer to the upstream
author's announcement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://article.gmane.org/gmane.mail.postfix.announce/110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1629"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postfix package.

For the stable distribution (etch), this problem has been fixed in
version 2.3.8-2+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"postfix", reference:"2.3.8-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postfix-cdb", reference:"2.3.8-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postfix-dev", reference:"2.3.8-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postfix-doc", reference:"2.3.8-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postfix-ldap", reference:"2.3.8-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postfix-mysql", reference:"2.3.8-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postfix-pcre", reference:"2.3.8-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postfix-pgsql", reference:"2.3.8-2+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
