#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-979-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48905);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-2575");
  script_bugtraq_id(42702);
  script_xref(name:"USN", value:"979-1");

  script_name(english:"Ubuntu 9.04 / 9.10 / 10.04 LTS : kdegraphics vulnerability (USN-979-1)");
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
"Stefan Cornelius of Secunia Research discovered a boundary error
during RLE decompression in the 'TranscribePalmImageToJPEG()' function
in generators/plucker/inplug/image.cpp of okular when processing
images embedded in PDB files, which can be exploited to cause a
heap-based buffer overflow. (CVE-2010-2575).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gwenview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kcolorchooser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-strigi-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kolourpaint4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdcraw7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdcraw7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdcraw8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdcraw8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkexiv2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkexiv2-7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkexiv2-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkexiv2-8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkipi6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkipi6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkipi7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkipi7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libksane-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libksane0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libokularcore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:okular-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:okular-extra-backends");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"gwenview", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kamera", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kcolorchooser", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdegraphics", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdegraphics-dbg", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdegraphics-strigi-plugins", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kgamma", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kolourpaint", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kolourpaint4", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kruler", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ksnapshot", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkdcraw7", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkdcraw7-dev", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkexiv2-7", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkexiv2-7-dev", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkipi6", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkipi6-dev", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libksane-dev", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libksane0", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libokularcore1", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"okular", pkgver:"4:4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"okular-dev", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"okular-extra-backends", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gwenview", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kamera", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kcolorchooser", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdegraphics", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdegraphics-dbg", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdegraphics-strigi-plugins", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kgamma", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kolourpaint4", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kruler", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ksnapshot", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkdcraw7", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkdcraw7-dev", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkexiv2-7", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkexiv2-7-dev", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkipi6", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkipi6-dev", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libksane-dev", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libksane0", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libokularcore1", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"okular", pkgver:"4:4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"okular-dev", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"okular-extra-backends", pkgver:"4.3.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gwenview", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kamera", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kcolorchooser", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kdegraphics", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kdegraphics-dbg", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kdegraphics-strigi-plugins", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kgamma", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kolourpaint4", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kruler", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ksnapshot", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkdcraw8", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkdcraw8-dev", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkexiv2-8", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkexiv2-8-dev", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkipi7", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkipi7-dev", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libksane-dev", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libksane0", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libokularcore1", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"okular", pkgver:"4:4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"okular-dev", pkgver:"4.4.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"okular-extra-backends", pkgver:"4.4.2-0ubuntu1.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gwenview / kamera / kcolorchooser / kdegraphics / kdegraphics-dbg / etc");
}
