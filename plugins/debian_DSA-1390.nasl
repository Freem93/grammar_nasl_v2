#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1390. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27545);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/03/19 14:28:18 $");

  script_cve_id("CVE-2007-4033");
  script_bugtraq_id(25079);
  script_xref(name:"DSA", value:"1390");

  script_name(english:"Debian DSA-1390-1 : t1lib - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hamid Ebadi discovered a buffer overflow in the
intT1_Env_GetCompletePath routine in t1lib, a Type 1 font rasterizer
library. This flaw could allow an attacker to crash an application
using the t1lib shared libraries, and potentially execute arbitrary
code within such an application's security context."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=439927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1390"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the t1lib package.

For the old stable distribution (sarge), this problem has been fixed
in version 5.0.2-3sarge1.

For the stable distribution (etch), this problem has been fixed in
version 5.1.0-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:t1lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libt1-5", reference:"5.0.2-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libt1-dev", reference:"5.0.2-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libt1-doc", reference:"5.0.2-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"t1lib-bin", reference:"5.0.2-3sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"libt1-5", reference:"5.1.0-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libt1-dev", reference:"5.1.0-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libt1-doc", reference:"5.1.0-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"t1lib-bin", reference:"5.1.0-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
