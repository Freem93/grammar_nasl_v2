#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-778. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19475);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-2556", "CVE-2005-2557", "CVE-2005-3090", "CVE-2005-3091");
  script_bugtraq_id(14604);
  script_osvdb_id(18900, 18901, 18902, 18903);
  script_xref(name:"DSA", value:"778");

  script_name(english:"Debian DSA-778-1 : mantis - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security related problems have been discovered in Mantis, a
web-based bug tracking system. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CAN-2005-2556
    A remote attacker could supply a specially crafted URL
    to scan arbitrary ports on arbitrary hosts that may not
    be accessible otherwise.

  - CAN-2005-2557

    A remote attacker was able to insert arbitrary HTML code
    in bug reports, hence, cross site scripting.

  - CAN-2005-3090

    A remote attacker was able to insert arbitrary HTML code
    in bug reports, hence, cross site scripting.

The old stable distribution (woody) does not seem to be affected by
these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-778"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mantis package.

For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mantis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mantis", reference:"0.19.2-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
