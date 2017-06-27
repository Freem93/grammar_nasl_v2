#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3517. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89926);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-1531");
  script_osvdb_id(135280);
  script_xref(name:"DSA", value:"3517");

  script_name(english:"Debian DSA-3517-1 : exim4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A local root privilege escalation vulnerability was found in Exim,
Debian's default mail transfer agent, in configurations using
the'perl_startup' option (Only Exim via exim4-daemon-heavy enables
Perl support).

To address the vulnerability, updated Exim versions clean the complete
execution environment by default, affecting Exim and subprocesses such
as transports calling other programs, and thus may break existing
installations. New configuration options (keep_environment,
add_environment) were introduced to adjust this behavior.

More information can be found in the upstream advisory at
https://www.exim.org/static/doc/CVE-2016-1531.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.exim.org/static/doc/CVE-2016-1531.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3517"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the exim4 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 4.80-7+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 4.84.2-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/15");
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
if (deb_check(release:"7.0", prefix:"exim4", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-base", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-config", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-heavy", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-light", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-light-dbg", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-dbg", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-dev", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"eximon4", reference:"4.80-7+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"exim4", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-base", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-config", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-heavy", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-light", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-light-dbg", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-dbg", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-dev", reference:"4.84.2-1")) flag++;
if (deb_check(release:"8.0", prefix:"eximon4", reference:"4.84.2-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
