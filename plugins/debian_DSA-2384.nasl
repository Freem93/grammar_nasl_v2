#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2384. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57524);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2010-1644", "CVE-2010-1645", "CVE-2010-2543", "CVE-2010-2545", "CVE-2011-4824");
  script_bugtraq_id(37109, 39639, 40332, 42575, 50671);
  script_osvdb_id(60566, 63972, 65014, 67369, 67505, 67506, 67507, 67508, 67509, 67510, 67511, 67512, 67513, 67514, 67515, 67516, 67517, 67518, 67519, 67520, 67521, 67522, 67523, 67524, 67525, 67526, 67527, 67528, 67529, 77097);
  script_xref(name:"DSA", value:"2384");

  script_name(english:"Debian DSA-2384-2 : cacti - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Cacti, a graphing tool
for monitoring data. Multiple cross site scripting issues allow remote
attackers to inject arbitrary web script or HTML. A SQL injection
vulnerability allows remote attackers to execute arbitrary SQL
commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/cacti"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2384"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cacti packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.8.7b-2.1+lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.7g-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"cacti", reference:"0.8.7b-2.1+lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"cacti", reference:"0.8.7g-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
