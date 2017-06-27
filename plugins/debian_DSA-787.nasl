#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-787. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19530);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/05/03 11:30:24 $");

  script_cve_id("CVE-2005-1855", "CVE-2005-1856");
  script_osvdb_id(27434);
  script_xref(name:"DSA", value:"787");

  script_name(english:"Debian DSA-787-1 : backup-manager - insecure permissions and tempfile");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two bugs have been found in backup-manager, a command-line driven
backup utility. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CAN-2005-1855
    Jeroen Vermeulen discovered that backup files are
    created with default permissions making them world
    readable, even though they may contain sensitive
    information.

  - CAN-2005-1856

    Sven Joachim discovered that the optional CD-burning
    feature of backup-manager uses a hard-coded filename in
    a world-writable directory for logging. This can be
    subject to a symlink attack.

The old stable distribution (woody) does not provide the
backup-manager package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=308897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=315582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-787"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the backup-manager package.

For the stable distribution (sarge) these problems have been fixed in
version 0.5.7-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:backup-manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"backup-manager", reference:"0.5.7-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
