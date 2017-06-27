#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3222. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82744);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_bugtraq_id(73948, 73955, 73956);
  script_osvdb_id(120393, 120394, 120395);
  script_xref(name:"DSA", value:"3222");

  script_name(english:"Debian DSA-3222-1 : chrony - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Miroslav Lichvar of Red Hat discovered multiple vulnerabilities in
chrony, an alternative NTP client and server :

  - CVE-2015-1821
    Using particular address/subnet pairs when configuring
    access control would cause an invalid memory write. This
    could allow attackers to cause a denial of service
    (crash) or execute arbitrary code.

  - CVE-2015-1822
    When allocating memory to save unacknowledged replies to
    authenticated command requests, a pointer would be left
    uninitialized, which could trigger an invalid memory
    write. This could allow attackers to cause a denial of
    service (crash) or execute arbitrary code.

  - CVE-2015-1853
    When peering with other NTP hosts using authenticated
    symmetric association, the internal state variables
    would be updated before the MAC of the NTP messages was
    validated. This could allow a remote attacker to cause a
    denial of service by impeding synchronization between
    NTP peers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chrony"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3222"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chrony packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.24-3.1+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chrony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"chrony", reference:"1.24-3.1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
