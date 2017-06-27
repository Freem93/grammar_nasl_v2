#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2348. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56881);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/14 15:20:31 $");

  script_cve_id("CVE-2010-4170", "CVE-2010-4171", "CVE-2011-2503");
  script_bugtraq_id(44914, 44917, 48886);
  script_osvdb_id(69489, 69490, 74148);
  script_xref(name:"DSA", value:"2348");

  script_name(english:"Debian DSA-2348-1 : systemtap - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in SystemTap, an
instrumentation system for Linux :

  - CVE-2011-2503
    It was discovered that a race condition in staprun could
    lead to privilege escalation. 

  - CVE-2010-4170
    It was discovered that insufficient validation of
    environment variables in staprun could lead to privilege
    escalation.

  - CVE-2010-4171
    It was discovered that insufficient validation of module
    unloading could lead to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/systemtap"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2348"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the systemtap packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2-5+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemtap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"systemtap", reference:"1.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"systemtap-client", reference:"1.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"systemtap-common", reference:"1.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"systemtap-doc", reference:"1.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"systemtap-grapher", reference:"1.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"systemtap-runtime", reference:"1.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"systemtap-sdt-dev", reference:"1.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"systemtap-server", reference:"1.2-5+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
