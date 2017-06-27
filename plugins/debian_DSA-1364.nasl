#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1364. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25964);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2007-2438", "CVE-2007-2953");
  script_osvdb_id(35488, 38674, 51434);
  script_xref(name:"DSA", value:"1364");

  script_name(english:"Debian DSA-1364-2 : vim - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the vim editor. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-2953
    Ulf Harnhammar discovered that a format string flaw in
    helptags_one() from src/ex_cmds.c (triggered through the
    'helptags' command) can lead to the execution of
    arbitrary code.

  - CVE-2007-2438
    Editors often provide a way to embed editor
    configuration commands (aka modelines) which are
    executed once a file is opened. Harmful commands are
    filtered by a sandbox mechanism. It was discovered that
    function calls to writefile(), feedkeys() and system()
    were not filtered, allowing shell command execution with
    a carefully crafted file opened in vim.

This updated advisory repairs issues with missing files in the
packages for the oldstable distribution (sarge) for the alpha, mips,
and mipsel architectures."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vim packages.

For the oldstable distribution (sarge) these problems have been fixed
in version 6.3-071+1sarge2. Sarge is not affected by CVE-2007-2438.

For the stable distribution (etch) these problems have been fixed in
version 7.0-122+1etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"vim", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-common", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-doc", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-full", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-gnome", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-gtk", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-lesstif", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-perl", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-python", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-ruby", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"vim-tcl", reference:"6.3-071+1sarge2")) flag++;
if (deb_check(release:"4.0", prefix:"vim", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-common", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-doc", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-full", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-gnome", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-gtk", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-gui-common", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-lesstif", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-perl", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-python", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-ruby", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-runtime", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-tcl", reference:"7.0-122+1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"vim-tiny", reference:"7.0-122+1etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
