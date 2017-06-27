#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2647. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65581);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-2492");
  script_bugtraq_id(58393);
  script_osvdb_id(91044);
  script_xref(name:"DSA", value:"2647");

  script_name(english:"Debian DSA-2647-1 : firebird2.1 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow was discovered in the Firebird database server,
which could result in the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/firebird2.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2647"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the firebird2.1 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.1.3.18185-0.ds1-11+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firebird Relational Database CNCT Group Number Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firebird2.1-classic", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.1-common", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.1-common-doc", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.1-dev", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.1-doc", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.1-examples", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.1-server-common", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"firebird2.1-super", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libfbembed2.1", reference:"2.1.3.18185-0.ds1-11+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
