#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-422. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15259);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_xref(name:"DSA", value:"422");

  script_name(english:"Debian DSA-422-1 : cvs - remote vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The account management of the CVS pserver (which is used to give
remote access to CVS repositories) uses a CVSROOT/passwd file in each
repository which contains the accounts and their authentication
information as well as the name of the local unix account to use when
a pserver account is used. Since CVS performed no checking on what
unix account was specified anyone who could modify the
CVSROOT/passwdcould gain access to all local users on the CVS server,
including root."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-422"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in upstream version 1.11.11 by preventing pserver
from running as root. For Debian this problem is solved in version
1.11.1p1debian-9 in two different ways :

  - pserver is no longer allowed to use root to access
    repositories
  - a new /etc/cvs-repouid is introduced which can be used
    by the system administrator to override the unix account
    used to access a repository. More information on this
    change can be found at

Additionally, CVS pserver had a bug in parsing module requests which
could be used to create files and directories outside a repository.
This has been fixed upstream in version 1.11.11 and Debian version
1.11.1p1debian-9.


Finally, the umask used for 'cvs init' and 'cvs-makerepos' has been
changed to prevent repositories from being created with group write
permissions."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/13");
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
if (deb_check(release:"3.0", prefix:"cvs", reference:"1.11.1p1debian-9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
