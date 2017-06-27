#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-160. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14997);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:49:54 $");

  script_cve_id("CVE-2002-0662");
  script_bugtraq_id(5602);
  script_xref(name:"DSA", value:"160");

  script_name(english:"Debian DSA-160-1 : scrollkeeper - insecure temporary file creation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Spybreak discovered a problem in scrollkeeper, a free electronic
cataloging system for documentation. The scrollkeeper-get-cl program
creates temporary files in an insecure manner in /tmp using guessable
filenames. Since scrollkeeper is called automatically when a user logs
into a Gnome session, an attacker with local access can easily create
and overwrite files as another user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-160"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the scrollkeeper packages immediately.

This problem has been fixed in version 0.3.6-3.1 for the current
stable distribution (woody) and in version 0.3.11-2 for the unstable
distribution (sid). The old stable distribution (potato) is not
affected, since it doesn't contain the scrollkeeper package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scrollkeeper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"3.0", prefix:"libscrollkeeper-dev", reference:"0.3.6-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"libscrollkeeper0", reference:"0.3.6-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"scrollkeeper", reference:"0.3.6-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
