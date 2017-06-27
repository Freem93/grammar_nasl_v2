#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-75-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82220);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:23:47 $");

  script_cve_id("CVE-2013-2162", "CVE-2014-0001", "CVE-2014-4274");
  script_bugtraq_id(60424, 65298, 69732);
  script_osvdb_id(102713, 109726);

  script_name(english:"Debian DLA-75-1 : mysql-5.1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-4274

Insecure handling of a temporary file that could lead to abritrary
execution of code through the creation of a mysql configuration file
pointing to an attacker-controlled plugin_dir.

CVE-2013-2162

Insecure creation of the debian.cnf credential file. Credentials could
be stolen by a local user monitoring that file while the package gets
installed.

CVE-2014-0001

Buffer overrun in the MySQL client when the server sends a version
string that is too big for the allocated buffer.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/10/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/mysql-5.1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqlclient16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqld-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-client-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-server-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-server-core-5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libmysqlclient-dev", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqlclient16", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-dev", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-pic", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client-5.1", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-common", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-5.1", reference:"5.1.73-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-core-5.1", reference:"5.1.73-1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
