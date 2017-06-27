#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3104. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80057);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/20 14:56:55 $");

  script_cve_id("CVE-2014-7844");
  script_osvdb_id(115954);
  script_xref(name:"DSA", value:"3104");

  script_name(english:"Debian DSA-3104-1 : bsd-mailx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that bsd-mailx, an implementation of the 'mail'
command, had an undocumented feature which treats syntactically valid
email addresses as shell commands to execute.

Users who need this feature can re-enable it using the 'expandaddr' in
an appropriate mailrc file. This update also removes the obsolete-T
option. An older security vulnerability, CVE-2004-2771, had already
been addressed in the Debian's bsd-mailx package.

Note that this security update does not remove all mailx facilities
for command execution, though. Scripts which send mail to addresses
obtained from an untrusted source (such as a web form) should use
the-- separator before the email addresses (which was fixed to work
properly in this update), or they should be changed to invokemail -t
or sendmail -i -t instead, passing the recipient addresses as part of
the mail header."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-2771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bsd-mailx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3104"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bsd-mailx packages.

For the stable distribution (wheezy), this problem has been fixed in
version 8.1.2-0.20111106cvs-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsd-mailx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"bsd-mailx", reference:"8.1.2-0.20111106cvs-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
