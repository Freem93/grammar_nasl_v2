#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3687. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93870);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2016-1951");
  script_osvdb_id(139631);
  script_xref(name:"DSA", value:"3687");

  script_name(english:"Debian DSA-3687-1 : nspr - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were reported in NSPR, a library to abstract over
operating system interfaces developed by the Mozilla project.

  - CVE-2016-1951
    q1 reported that the NSPR implementation of
    sprintf-style string formatting function miscomputed
    memory allocation sizes, potentially leading to
    heap-based buffer overflows

The second issue concerns environment variable processing in NSPR. The
library did not ignore environment variables used to configuring
logging and tracing in processes which underwent a SUID/SGID/AT_SECURE
transition at process start. In certain system configurations, this
allowed local users to escalate their privileges.

In addition, this nspr update contains further stability and
correctness fixes and contains support code for an upcoming nss
update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=583651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nspr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3687"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nspr packages.

For the stable distribution (jessie), these problems have been fixed
in version 2:4.12-1+debu8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/06");
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
if (deb_check(release:"8.0", prefix:"libnspr4", reference:"2:4.12-1+debu8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnspr4-0d", reference:"2:4.12-1+debu8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnspr4-dbg", reference:"2:4.12-1+debu8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnspr4-dev", reference:"2:4.12-1+debu8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
