#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1177. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22719);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-4246");
  script_osvdb_id(28915);
  script_xref(name:"DSA", value:"1177");

  script_name(english:"Debian DSA-1177-1 : usermin - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hendrik Weimer discovered that it is possible for a normal user to
disable the login shell of the root account via usermin, a web-based
administration tool."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=374609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1177"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the usermin package.

For the stable distribution (sarge) this problem has been fixed in
version 1.110-3.1.

In the upstream distribution this problem is fixed in version 1.220."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usermin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"usermin", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-at", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-changepass", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-chfn", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-commands", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-cron", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-cshrc", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-fetchmail", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-forward", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-gnupg", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-htaccess", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-htpasswd", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-mailbox", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-man", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-mysql", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-plan", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-postgresql", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-proc", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-procmail", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-quota", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-schedule", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-shell", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-spamassassin", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-ssh", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-tunnel", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-updown", reference:"1.110-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"usermin-usermount", reference:"1.110-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
