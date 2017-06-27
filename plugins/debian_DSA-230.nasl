#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-230. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15067);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:02:52 $");

  script_cve_id("CVE-2003-0012", "CVE-2003-0013");
  script_bugtraq_id(6501, 6502);
  script_osvdb_id(6351, 6352);
  script_xref(name:"DSA", value:"230");

  script_name(english:"Debian DSA-230-1 : bugzilla - insecure permissions, spurious backup files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in Bugzilla, a web-based bug
tracking system, by its authors. The Common Vulnerabilities and
Exposures Project identifies the following vulnerabilities :

CAN-2003-0012 (BugTraq ID 6502)

    The provided data collection script intended to be run as a
    nightly cron job changes the permissions of the data/mining
    directory to be world-writable every time it runs. This would
    enable local users to alter or delete the collected data.

CAN-2003-0013 (BugTraq ID 6501)

    The default .htaccess scripts provided by checksetup.pl do not
    block access to backups of the localconfig file that might be
    created by editors such as vi or emacs (typically these will have
    a .swp or ~ suffix). This allows an end user to download one of
    the backup copies and potentially obtain your database password.

    This does not affect the Debian installation because there is no
    .htaccess as all data file aren't under the CGI path as they are
    on the standard Bugzilla package. Additionally, the configuration
    is in /etc/bugzilla/localconfig and hence outside of the web
    directory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-230"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bugzilla packages.

For the current stable distribution (woody) these problems have been
fixed in version 2.14.2-0woody4.

The old stable distribution (potato) does not contain a Bugzilla
package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/03");
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
if (deb_check(release:"3.0", prefix:"bugzilla", reference:"2.14.2-0woody4")) flag++;
if (deb_check(release:"3.0", prefix:"bugzilla-doc", reference:"2.14.2-0woody4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
