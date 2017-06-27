#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-751-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96012);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/21 19:25:20 $");

  script_cve_id("CVE-2016-9565", "CVE-2016-9566");
  script_osvdb_id(49261, 148437);

  script_name(english:"Debian DLA-751-1 : nagios3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nagios was found to be vulnerable to two security issues that, when
combined, lead to a remote root code execution vulnerability.
Fortunately, the hardened permissions of the Debian package limit the
effect of those to information disclosure, but privilege escalation to
root is still possible locally.

CVE-2016-9565

Improper sanitization of RSS feed input enables unauthenticated remote
read and write of arbitrary files which may lead to remote code
execution if the web root is writable.

CVE-2016-9566

Unsafe logfile handling allows unprivileged users to escalate their
privileges to root. In wheezy, this is possible only through the debug
logfile which is disabled by default.

For Debian 7 'Wheezy', these problems have been fixed in version
3.4.1-3+deb7u3.

We recommend that you upgrade your nagios3 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nagios3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"nagios3", reference:"3.4.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"nagios3-cgi", reference:"3.4.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"nagios3-common", reference:"3.4.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"nagios3-core", reference:"3.4.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"nagios3-dbg", reference:"3.4.1-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"nagios3-doc", reference:"3.4.1-3+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
