#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-158-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82141);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-9472", "CVE-2015-1165", "CVE-2015-1464");
  script_bugtraq_id(72832, 72833, 72837);

  script_name(english:"Debian DLA-158-1 : request-tracker3.8 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Request Tracker, an
extensible trouble-ticket tracking system. The Common Vulnerabilities
and Exposures project identifies the following problems :

CVE-2014-9472

Christian Loos discovered a remote denial of service vulnerability,
exploitable via the email gateway and affecting any installation which
accepts mail from untrusted sources. Depending on RT's logging
configuration, a remote attacker can take advantage of this flaw to
cause CPU and excessive disk usage.

CVE-2015-1165

Christian Loos discovered an information disclosure flaw which may
reveal RSS feeds URLs, and thus ticket data.

CVE-2015-1464

It was discovered that RSS feed URLs can be leveraged to perform
session hijacking, allowing a user with the URL to log in as the user
that created the feed.

For the oldstable distribution (squeeze), these problems have been
fixed in version 3.8.8-7+squeeze9.

We recommend that you upgrade your request-tracker3.8 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/02/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/request-tracker3.8"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt3.8-apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt3.8-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt3.8-db-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt3.8-db-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt3.8-db-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"request-tracker3.8", reference:"3.8.8-7+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-apache2", reference:"3.8.8-7+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-clients", reference:"3.8.8-7+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-mysql", reference:"3.8.8-7+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-postgresql", reference:"3.8.8-7+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-sqlite", reference:"3.8.8-7+squeeze8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
