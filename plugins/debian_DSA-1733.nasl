#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1733. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35764);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101");
  script_xref(name:"DSA", value:"1733");

  script_name(english:"Debian DSA-1733-1 : vim - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in vim, an enhanced vi editor.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2008-2712
    Jan Minar discovered that vim did not properly sanitise
    inputs before invoking the execute or system functions
    inside vim scripts. This could lead to the execution of
    arbitrary code.

  - CVE-2008-3074
    Jan Minar discovered that the tar plugin of vim did not
    properly sanitise the filenames in the tar archive or
    the name of the archive file itself, making it prone to
    arbitrary code execution.

  - CVE-2008-3075
    Jan Minar discovered that the zip plugin of vim did not
    properly sanitise the filenames in the zip archive or
    the name of the archive file itself, making it prone to
    arbitrary code execution.

  - CVE-2008-3076
    Jan Minar discovered that the netrw plugin of vim did
    not properly sanitise the filenames or directory names
    it is given. This could lead to the execution of
    arbitrary code.

  - CVE-2008-4101
    Ben Schmidt discovered that vim did not properly escape
    characters when performing keyword or tag lookups. This
    could lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=486502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=506919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1733"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the oldstable distribution (etch), these problems have been fixed
in version 1:7.0-122+1etch5.

For the stable distribution (lenny), these problems have been fixed in
version 1:7.1.314-3+lenny1, which was already included in the lenny
release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 78, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"vim", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-common", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-doc", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-full", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-gnome", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-gtk", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-gui-common", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-lesstif", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-perl", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-python", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-ruby", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-runtime", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-tcl", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"vim-tiny", reference:"1:7.0-122+1etch5")) flag++;
if (deb_check(release:"5.0", prefix:"vim", reference:"1:7.1.314-3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
