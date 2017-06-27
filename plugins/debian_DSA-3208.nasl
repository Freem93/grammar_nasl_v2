#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3208. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82305);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2015-2753", "CVE-2015-2754", "CVE-2015-2776");
  script_bugtraq_id(73330);
  script_osvdb_id(119976, 119980, 119981);
  script_xref(name:"DSA", value:"3208");

  script_name(english:"Debian DSA-3208-1 : freexl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jodie Cunningham discovered multiple vulnerabilities in freexl, a
library to read Microsoft Excel spreadsheets, which might result in
denial of service or the execution of arbitrary code if a malformed
Excel file is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/freexl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3208"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freexl packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.0.0b-1+deb7u1.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 1.0.0g-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freexl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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
if (deb_check(release:"7.0", prefix:"libfreexl-dev", reference:"1.0.0b-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libfreexl1", reference:"1.0.0b-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libfreexl1-dbg", reference:"1.0.0b-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
