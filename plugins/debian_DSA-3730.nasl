#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3730. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95666);
  script_version("$Revision: 3.7 $");
  script_cvs_date("$Date: 2017/01/24 14:51:33 $");

  script_cve_id("CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9066", "CVE-2016-9074", "CVE-2016-9079");
  script_osvdb_id(147338, 147342, 147345, 147352, 147362, 147375, 147376, 147377, 147378, 147379, 147380, 147381, 147382, 147383, 147384, 147385, 147386, 147993);
  script_xref(name:"DSA", value:"3730");

  script_name(english:"Debian DSA-3730-1 : icedove - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail client: Multiple memory safety errors,
same-origin policy bypass issues, integer overflows, buffer overflows
and use-after-frees may lead to the execution of arbitrary code or
denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3730"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (jessie), these problems have been fixed
in version 1:45.5.1-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSMILTimeContainer::NotifyTimeChange() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"calendar-google-provider", reference:"1:45.5.1-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove", reference:"1:45.5.1-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dbg", reference:"1:45.5.1-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dev", reference:"1:45.5.1-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceowl-extension", reference:"1:45.5.1-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
