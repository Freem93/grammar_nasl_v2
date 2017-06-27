#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-043. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14880);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0568", "CVE-2001-0569");
  script_bugtraq_id(2458);
  script_osvdb_id(6285, 6286);
  script_xref(name:"DSA", value:"043");

  script_name(english:"Debian DSA-043-1 : zope");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This advisory covers several vulnerabilities in Zope that have been
addressed.Hotfix 08_09_2000 'Zope security alert and hotfix product'
The issue involves the fact that the getRoles method of user objects
contained in the default UserFolder implementation returns a mutable
Python type. Because the mutable object is still associated with the
persistent User object, users with the ability to edit DTML could
arrange to give themselves extra roles for the duration of a single
request by mutating the roles list as a part of the request
processing.Hotfix 2000-10-02 'ZPublisher security update' It is
sometimes possible to access, through a URL only, objects protected by
a role which the user has in some context, but not in the context of
the accessed object.Hotfix 2000-10-11 'ObjectManager subscripting' The
issue involves the fact that the 'subscript notation' that can be used
to access items of ObjectManagers (Folders) did not correctly restrict
return values to only actual sub items. This made it possible to
access names that should be private from DTML (objects with names
beginning with the underscore '_' character). This could allow DTML
authors to see private implementation data structures and in certain
cases possibly call methods that they shouldn't have access to from
DTML.Hotfix 2001-02-23 'Class attribute access' The issue is related
to ZClasses in that a user with through-the-web scripting capabilities
on a Zope site can view and assign class attributes to ZClasses,
possibly allowing them to make inappropriate changes to ZClass
instances. A second part fixes problems in the ObjectManager,
PropertyManager, and PropertySheet classes related to mutability of
method return values which could be perceived as a security
problem.These fixes are included in zope 2.1.6-7 for Debian 2.2
(potato). We recommend you upgrade your zope package immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-043"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected zope package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zope");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/15");
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
if (deb_check(release:"2.2", prefix:"zope", reference:"2.1.6-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
