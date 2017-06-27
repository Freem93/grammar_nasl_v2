#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-622-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93544);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-1240");
  script_osvdb_id(144341);

  script_name(english:"Debian DLA-622-1 : tomcat6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dawid Golunski from legalhackers.com discovered that Debian's version
of Tomcat 6 was vulnerable to a local privilege escalation. Local
attackers who have gained access to the server in the context of the
tomcat6 user through a vulnerability in a web application were able to
replace the file with a symlink to an arbitrary file.

The full advisory can be found at

http://legalhackers.com/advisories/Tomcat-Debian-based-Root-Privilege-
Es calation-Exploit.txt

For Debian 7 'Wheezy', these problems have been fixed in version
6.0.45+dfsg-1~deb7u2.

We recommend that you upgrade your tomcat6 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # http://legalhackers.com/advisories/Tomcat-Debian-based-Root-Privilege-Es
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0b304c1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tomcat6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");
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
if (deb_check(release:"7.0", prefix:"libservlet2.4-java", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet2.5-java", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet2.5-java-doc", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libtomcat6-java", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-admin", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-common", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-docs", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-examples", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-extras", reference:"6.0.45+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-user", reference:"6.0.45+dfsg-1~deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
