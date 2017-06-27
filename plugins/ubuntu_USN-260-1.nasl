#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-260-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21072);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2006-0459");
  script_osvdb_id(23440);
  script_xref(name:"USN", value:"260-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : flex vulnerability (USN-260-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Moore discovered a buffer overflow in a particular class of
lexicographical scanners generated by flex. This could be exploited to
execute arbitrary code by processing specially crafted user-defined
input to an application that uses a flex scanner for parsing.

This flaw particularly affects gpc, the GNU Pascal Compiler. A
potentially remote attacker could exploit this by tricking an user or
automated system into compiling a specially crafted Pascal source code
file.

Please note that gpc is not officially supported in Ubuntu (it is in
the 'universe' component of the archive). However, this affects you if
you use a customized version built from the gcc-3.3 or gcc-3.4 source
package (which is supported).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cpp-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cpp-3.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cpp-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cpp-3.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fastjar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fixincludes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g++-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g++-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g77-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g77-3.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g77-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g77-3.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-3.3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-3.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-3.4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-3.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gij-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gij-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnat-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnat-3.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnat-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnat-3.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gobjc-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gobjc-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpc-2.1-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpc-2.1-3.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpc-2.1-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpc-2.1-3.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32g2c0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32gcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32stdc++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32stdc++6-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64g2c0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64gcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64stdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libffi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libffi2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libffi3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libffi3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libg2c0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libg2c0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj4-awt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj5-awt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnat-3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libobjc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++5-3.3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++5-3.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++5-3.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++5-3.3-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-0-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:protoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:treelang-3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:treelang-3.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"cpp-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cpp-3.3-doc", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cpp-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cpp-3.4-doc", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"fastjar", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"fixincludes", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"flex", pkgver:"2.5.31-26ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"flex-doc", pkgver:"2.5.31-26ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"g++-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"g++-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"g77-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"g77-3.3-doc", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"g77-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"g77-3.4-doc", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcc-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcc-3.3-base", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcc-3.3-doc", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcc-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcc-3.4-base", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcc-3.4-doc", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcj-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gcj-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gij-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gij-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gnat-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gnat-3.3-doc", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gnat-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gnat-3.4-doc", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gobjc-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gobjc-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gpc-2.1-3.3", pkgver:"3.3.4.20040516-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gpc-2.1-3.3-doc", pkgver:"3.3.4.20040516-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gpc-2.1-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gpc-2.1-3.4-doc", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"lib32gcc1", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"lib32stdc++5", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"lib32stdc++6-0", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"lib64gcc1", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"lib64stdc++6", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libffi2", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libffi2-dev", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libffi3", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libffi3-dev", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libg2c0", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libg2c0-dev", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcc1", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj-common", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj4", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj4-awt", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj4-common", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj4-dev", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj5", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj5-awt", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj5-common", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgcj5-dev", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgnat-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libobjc1", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++5", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++5-3.3-dbg", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++5-3.3-dev", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++5-3.3-doc", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++5-3.3-pic", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-0", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-0-dbg", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-0-dev", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-0-pic", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-dbg", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-dev", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-doc", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libstdc++6-pic", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"protoize", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"treelang-3.3", pkgver:"3.3.4-9ubuntu5.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"treelang-3.4", pkgver:"3.4.2-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"cpp-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"cpp-3.3-doc", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"cpp-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"cpp-3.4-doc", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"flex", pkgver:"2.5.31-31ubuntu0.5.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"flex-doc", pkgver:"2.5.31-31ubuntu0.5.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"g++-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"g++-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"g77-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"g77-3.3-doc", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"g77-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"g77-3.4-doc", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcc-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcc-3.3-base", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcc-3.3-doc", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcc-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcc-3.4-base", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcc-3.4-doc", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcj-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gcj-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gij-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gij-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnat-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnat-3.3-doc", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnat-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnat-3.4-doc", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gobjc-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gobjc-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gpc-2.1-3.3", pkgver:"3.3.5.20040516-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gpc-2.1-3.3-doc", pkgver:"3.3.5.20040516-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gpc-2.1-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gpc-2.1-3.4-doc", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"lib32stdc++6-0", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libffi2", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libffi2-dev", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libffi3", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libffi3-dev", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libg2c0", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libg2c0-dev", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj4", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj4-awt", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj4-common", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj4-dev", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj5", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj5-awt", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj5-common", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgcj5-dev", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgnat-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++5", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++5-3.3-dbg", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++5-3.3-dev", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++5-3.3-doc", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++5-3.3-pic", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-0", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-0-dbg", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-0-dev", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-0-pic", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-dbg", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-dev", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-doc", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstdc++6-pic", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"treelang-3.3", pkgver:"3.3.5-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"treelang-3.4", pkgver:"3.4.3-9ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"cpp-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"cpp-3.4-doc", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"flex", pkgver:"2.5.31-31ubuntu0.5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"flex-doc", pkgver:"2.5.31-31ubuntu0.5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"g++-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"g77-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"g77-3.4-doc", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gcc-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gcc-3.4-base", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gcc-3.4-doc", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gnat-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gnat-3.4-doc", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gobjc-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gpc-2.1-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gpc-2.1-3.4-doc", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"lib32g2c0", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"lib64g2c0", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libg2c0", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libg2c0-dev", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgnat-3.4", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libstdc++6-dbg", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libstdc++6-dev", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libstdc++6-doc", pkgver:"3.4.4-6ubuntu8.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libstdc++6-pic", pkgver:"3.4.4-6ubuntu8.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp-3.3 / cpp-3.3-doc / cpp-3.4 / cpp-3.4-doc / fastjar / etc");
}
