#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-109. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14946);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/08/13 14:23:42 $");

  script_cve_id("CVE-2002-0230");
  script_xref(name:"DSA", value:"109");

  script_name(english:"Debian DSA-109-1 : faqomatic - XSS vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to unescaped HTML code Faq-O-Matic returned unverified scripting
code to the browser. With some tweaking this enables an attacker to
steal cookies from one of the Faq-O-Matic moderators or the admin.

Cross-Site Scripting is a type of problem that allows a malicious
person to make another person run some JavaScript in their browser.
The JavaScript is executed on the victims machine and is in the
context of the website running the Faq-O-Matic Frequently Asked
Question manager."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-109"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the faqomatic package if you have it installed.

This problem has been fixed in version 2.603-1.2 for the stable Debian
distribution and version 2.712-2 for the current testing/unstable
distribution."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:faqomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"faqomatic", reference:"2.603-1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
