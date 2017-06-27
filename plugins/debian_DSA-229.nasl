#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-229. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15066);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/11/05 11:41:02 $");

  script_cve_id("CVE-2003-0025");
  script_bugtraq_id(6559);
  script_xref(name:"DSA", value:"229");

  script_name(english:"Debian DSA-229-1 : imp - SQL injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jouko Pynnonen discovered a problem with IMP, a web-based IMAP mail
program. Using carefully crafted URLs a remote attacker is able to
inject SQL code into SQL queries without proper user authentication.
Even though results of SQL queries aren't directly readable from the
screen, an attacker might update their mail signature to contain
wanted query results and then view it on the preferences page of IMP.

The impact of SQL injection depends heavily on the underlying database
and its configuration. If PostgreSQL is used, it's possible to execute
multiple complete SQL queries separated by semicolons. The database
contains session id's so the attacker might hijack sessions of people
currently logged in and read their mail. In the worst case, if the
hordemgr user has the required privilege to use the COPY SQL command
(found in PostgreSQL at least), a remote user may read or write to any
file the database user (postgres) can. The attacker may then be able
to run arbitrary shell commands by writing them to the postgres user's
~/.psqlrc; they'd be run when the user starts the psql command which
under some configurations happens regularly from a cron script."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-229"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the IMP packages.

For the current stable distribution (woody) this problem has been
fixed in version 2.2.6-5.1.

For the old stable distribution (potato) this problem has been fixed
in version 2.2.6-0.potato.5.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/15");
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
if (deb_check(release:"2.2", prefix:"imp", reference:"2.2.6-0.potato.5.1")) flag++;
if (deb_check(release:"3.0", prefix:"imp", reference:"2.2.6-5.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
