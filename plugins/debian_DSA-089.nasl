#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-089. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14926);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/06 20:12:49 $");

  script_cve_id("CVE-2001-0197", "CVE-2001-0784", "CVE-2001-1083", "CVE-2001-1230");
  script_bugtraq_id(2264, 2932, 2933);
  script_osvdb_id(1883, 10444);
  script_xref(name:"DSA", value:"089");

  script_name(english:"Debian DSA-089-2 : icecast-server - remote root exploit (and others)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The icecast-server (a streaming music server) package as distributed
in Debian GNU/Linux 2.2 has several security problems :

  - if a client added a / after the filename of a file to be
    downloaded the server would crash
  - by escaping dots as %2E it was possible to circumvent
    security measures and download arbitrary files

  - there were several buffer overflows that could be
    exploited to gain root access

These have been fixed in version 1.3.10-1, and we strongly recommend
that you upgrade your icecast-server package immediately.


The i386 package mentioned in the DSA-089-1 advisory was incorrectly
compiled and will not run on Debian GNU/Linux potato machines. This
has been corrected in version 1.3.10-1.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-089"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected icecast-server package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icecast-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"icecast-server", reference:"1.3.10-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
