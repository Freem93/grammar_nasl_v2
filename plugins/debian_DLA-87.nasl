#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-87-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82232);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_cve_id("CVE-2014-3477", "CVE-2014-3638", "CVE-2014-3639");
  script_bugtraq_id(67986, 69832, 69833, 69834);
  script_osvdb_id(108033, 111639, 111640);

  script_name(english:"Debian DLA-87-1 : dbus security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates fixes multiple (local) denial of services discovered by
Alban Crequy and Simon McVittie.

CVE-2014-3477

Fix a denial of service (failure to obtain bus name) in
newly-activated system services that not all users are allowed to
access.

CVE-2014-3638

Reduce maximum number of pending replies per connection to avoid
algorithmic complexity denial of service.

CVE-2014-3639

The daemon now limits the number of unauthenticated connection slots
so that malicious processes cannot prevent new connections to the
system bus.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/11/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/dbus"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus-1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdbus-1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"dbus", reference:"1.2.24-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"dbus-1-dbg", reference:"1.2.24-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"dbus-1-doc", reference:"1.2.24-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"dbus-x11", reference:"1.2.24-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libdbus-1-3", reference:"1.2.24-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libdbus-1-dev", reference:"1.2.24-4+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
