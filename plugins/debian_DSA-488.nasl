#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-488. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15325);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2004-0404");
  script_bugtraq_id(10162);
  script_osvdb_id(5495);
  script_xref(name:"DSA", value:"488");

  script_name(english:"Debian DSA-488-1 : logcheck - insecure temporary directory");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Jaeger reported a bug in logcheck which could potentially be
exploited by a local user to overwrite files with root privileges.
logcheck utilized a temporary directory under /var/tmp without taking
security precautions. While this directory is created when logcheck is
installed, and while it exists there is no vulnerability, if at any
time this directory is removed, the potential for exploitation exists."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) this problem has been
fixed in version 1.1.1-13.1woody1.

We recommend that you update your logcheck package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:logcheck");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"logcheck", reference:"1.1.1-13.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"logcheck-database", reference:"1.1.1-13.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"logtail", reference:"1.1.1-13.1woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
