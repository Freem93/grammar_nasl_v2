#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2472. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59166);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-0208");
  script_bugtraq_id(53123);
  script_osvdb_id(81395);
  script_xref(name:"DSA", value:"2472");

  script_name(english:"Debian DSA-2472-1 : gridengine - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dave Love discovered that users who are allowed to submit jobs to a
Grid Engine installation can escalate their privileges to root because
the environment is not properly sanitized before creating processes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gridengine"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2472"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gridengine packages.

For the stable distribution (squeeze), this problem has been fixed in
version 6.2u5-1squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gridengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
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
if (deb_check(release:"6.0", prefix:"gridengine-client", reference:"6.2u5-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gridengine-common", reference:"6.2u5-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gridengine-exec", reference:"6.2u5-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gridengine-master", reference:"6.2u5-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gridengine-qmon", reference:"6.2u5-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libdrmaa-dev", reference:"6.2u5-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libdrmaa-java", reference:"6.2u5-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libdrmaa1.0", reference:"6.2u5-1squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
