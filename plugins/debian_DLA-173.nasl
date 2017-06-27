#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-173-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82158);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2015-2157");
  script_bugtraq_id(72825);
  script_osvdb_id(118932);

  script_name(english:"Debian DLA-173-1 : putty security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MATTA-2015-002

Florent Daigniere discovered that PuTTY did not enforce an acceptable
range for the Diffie-Hellman server value, as required by RFC 4253,
potentially allowing an eavesdroppable connection to be established in
the event of a server weakness.

#779488 CVE-2015-2157

Patrick Coleman discovered that PuTTY did not clear SSH-2 private key
information from memory when loading and saving key files, which could
result in disclosure of private key material.

-- Colin Watson [cjwatson@debian.org]

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/03/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/putty"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/15");
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
if (deb_check(release:"6.0", prefix:"pterm", reference:"0.60+2010-02-20-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"putty", reference:"0.60+2010-02-20-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"putty-doc", reference:"0.60+2010-02-20-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"putty-tools", reference:"0.60+2010-02-20-1+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");