#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-526-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91832);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/06/27 14:51:42 $");

  script_cve_id("CVE-2015-2575");
  script_bugtraq_id(74075);
  script_osvdb_id(120721);

  script_name(english:"Debian DLA-526-1 : mysql-connector-java security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability in the MySQL Connectors component of Oracle MySQL
(subcomponent: Connector/J) has been discovered that may result in
unauthorized update, insert or delete access to some MySQL Connectors
accessible data as well as read access to a subset of MySQL
Connectors. The issue is addressed by updating to the latest stable
release of mysql-connector-java since Oracle did not release further
information.

Please see Oracle's Critical Patch Update advisory for further
details.

http://www.oracle.com/technetwork/topics/security/cpuapr2015verbose-23
65613.html#MSQL

For Debian 7 'Wheezy', these problems have been fixed in version
5.1.39-1~deb7u1.

We recommend that you upgrade your mysql-connector-java packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015verbose-2365613.html#MSQL
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e75fe00b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/06/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mysql-connector-java"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libmysql-java package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysql-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");
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
if (deb_check(release:"7.0", prefix:"libmysql-java", reference:"5.1.39-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
