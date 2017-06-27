#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2362. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57502);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-1159", "CVE-2011-2777", "CVE-2011-4578");
  script_bugtraq_id(45915, 50945, 50993);
  script_xref(name:"DSA", value:"2362");

  script_name(english:"Debian DSA-2362-1 : acpid - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in the ACPI Daemon, the Advanced
Configuration and Power Interface event daemon :

  - CVE-2011-1159
    Vasiliy Kulikov of OpenWall discovered that the socket
    handling is vulnerable to denial of service.

  - CVE-2011-2777
    Oliver-Tobias Ripka discovered that incorrect process
    handling in the Debian-specific powerbtn.sh script could
    lead to local privilege escalation. This issue doesn't
    affect oldstable. The script is only shipped as an
    example in /usr/share/doc/acpid/examples. See
    /usr/share/doc/acpid/README.Debian for details.

  - CVE-2011-4578
    Helmut Grohne and Michael Biebl discovered that acpid
    sets a umask of 0 when executing scripts, which could
    result in local privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/acpid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2362"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the acpid packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.8-1lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 1:2.0.7-1squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:acpid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/10");
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
if (deb_check(release:"5.0", prefix:"acpid", reference:"1.0.8-1lenny4")) flag++;
if (deb_check(release:"6.0", prefix:"acpid", reference:"1:2.0.7-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kacpimon", reference:"1:2.0.7-1squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
