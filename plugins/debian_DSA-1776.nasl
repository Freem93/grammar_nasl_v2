#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1776. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36207);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/17 23:49:56 $");

  script_cve_id("CVE-2009-2084");
  script_osvdb_id(56288);
  script_xref(name:"DSA", value:"1776");

  script_name(english:"Debian DSA-1776-1 : slurm-llnl - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Simple Linux Utility for Resource
Management (SLURM), a cluster job management and scheduling system,
did not drop the supplemental groups. These groups may be system
groups with elevated privileges, which may allow a valid SLURM user to
gain elevated privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=524980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1776"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the slurm-llnl package.

The old stable distribution (etch) does not contain a slurm-llnl
package.

For the stable distribution (lenny), this problem has been fixed in
version 1.3.6-1lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-llnl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpmi0", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libpmi0-dev", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libslurm13", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libslurm13-dev", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"slurm-llnl", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"slurm-llnl-basic-plugins", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"slurm-llnl-basic-plugins-dev", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"slurm-llnl-doc", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"slurm-llnl-slurmdbd", reference:"1.3.6-1lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"slurm-llnl-sview", reference:"1.3.6-1lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
