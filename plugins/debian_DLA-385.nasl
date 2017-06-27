#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-385-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87931);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-8605");
  script_osvdb_id(132709);

  script_name(english:"Debian DLA-385-2 : isc-dhcp regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"With the previous upload of the isc-dhcp package to Debian Squeeze LTS
two issues got introduced into LTS that are resolved by this upload.

(1)

CVE-2015-8605 had only been resolved for the LDAP variant of the DHCP
server package built from the isc-dhcp source package. With upload of
version 4.1.1-P1-15+squeeze10, now all DHCP server variants (LDAP and
non-LDAP alike) include the fix for CVE-2015-8605. Thanks to Ben
Hutchings for spotting this inaccuracy.

(2)

The amd64 binary build of the previously uploaded isc-dhcp version
(4.1.1-P1-15+squeeze9) was flawed and searched for the dhcpd.conf
configuration file at the wrong location [1,2,3]. This flaw in the
amd64 build had been caused by a not-100%-pure-squeeze-lts build
system on the maintainer's end. The amd64 build of version
4.1.1-P1-15+squeeze10 has been redone in a brand-new build environment
and does not show the reported symptom(s) anymore.

I deeply apologize for the experienced inconvenience to all who
encountered this issue.

[1] https://bugs.debian.org/811097 [2] https://bugs.debian.org/811397
[3] https://bugs.debian.org/811402

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/811097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/811397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/811402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/01/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/isc-dhcp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp3-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp3-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp3-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");
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
if (deb_check(release:"6.0", prefix:"dhcp3-client", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-common", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-dev", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-relay", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-server", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-dbg", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-udeb", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-common", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-dev", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay-dbg", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-dbg", reference:"4.1.1-P1-15+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-ldap", reference:"4.1.1-P1-15+squeeze10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
