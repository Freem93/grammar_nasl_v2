#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-048. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14885);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0406");
  script_bugtraq_id(2617);
  script_osvdb_id(13870, 13871, 13872);
  script_xref(name:"DSA", value:"048");

  script_name(english:"Debian DSA-048-3 : samba");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marcus Meissner discovered that samba was not creating temporary
 files safely in two places :

  - when a remote user queried a printer queue samba would
    create a temporary file in which the queue data would be
    written. This was being done using a predictable
    filename, and insecurely, allowing a local attacker to
    trick samba into overwriting arbitrary files.
  - smbclient 'more' and 'mput' commands also created
    temporary files in /tmp insecurely.

Both problems have been fixed in version 2.0.7-3.2, and we recommend
that you upgrade your samba package immediately. (This problem is also
fixed in the Samba 2.2 codebase.)


Note: DSA-048-1 included an incorrectly compiled sparc package, which
the second edition fixed.

The third edition of the advisory was made because Marc Jacobsen from
HP discovered that the security fixes from samba 2.0.8 did not fully
fix the /tmp symlink attack problem. The samba team released version
2.0.9 to fix that, and those fixes have been added to version
2.0.7-3.3 of the Debian samba packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-048"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected samba package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/17");
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
if (deb_check(release:"2.2", prefix:"samba", reference:"2.0.7-3.3")) flag++;
if (deb_check(release:"2.2", prefix:"samba-common", reference:"2.0.7-3.3")) flag++;
if (deb_check(release:"2.2", prefix:"samba-doc", reference:"2.0.7-3.3")) flag++;
if (deb_check(release:"2.2", prefix:"smbclient", reference:"2.0.7-3.3")) flag++;
if (deb_check(release:"2.2", prefix:"smbfs", reference:"2.0.7-3.3")) flag++;
if (deb_check(release:"2.2", prefix:"swat", reference:"2.0.7-3.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
