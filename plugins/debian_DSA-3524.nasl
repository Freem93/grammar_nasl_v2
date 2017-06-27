#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3524. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90071);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-5254");
  script_osvdb_id(131525);
  script_xref(name:"DSA", value:"3524");

  script_name(english:"Debian DSA-3524-1 : activemq - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the ActiveMQ Java message broker performs
unsafe deserialisation. For additional information, please refer to
the upstream advisory at
http://activemq.apache.org/security-advisories.data/CVE-2015-5254-anno
uncement.txt."
  );
  # http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?863a18c3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/activemq"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/activemq"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3524"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the activemq packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 5.6.0+dfsg-1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 5.6.0+dfsg1-4+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:activemq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/22");
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
if (deb_check(release:"7.0", prefix:"activemq", reference:"5.6.0+dfsg-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libactivemq-java", reference:"5.6.0+dfsg-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libactivemq-java-doc", reference:"5.6.0+dfsg-1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"activemq", reference:"5.6.0+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libactivemq-java", reference:"5.6.0+dfsg1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libactivemq-java-doc", reference:"5.6.0+dfsg1-4+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
