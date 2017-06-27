#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:287. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(42215);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_bugtraq_id(36703);
  script_xref(name:"MDVSA", value:"2009:287-1");

  script_name(english:"Mandriva Linux Security Advisory : xpdf (MDVSA-2009:287-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in xpdf :

Integer overflow in the SplashBitmap::SplashBitmap function in Xpdf
3.x before 3.02pl4 and Poppler before 0.12.1 might allow remote
attackers to execute arbitrary code via a crafted PDF document that
triggers a heap-based buffer overflow. NOTE: some of these details are
obtained from third-party information. NOTE: this issue reportedly
exists because of an incomplete fix for CVE-2009-1188 (CVE-2009-3603).

The Splash::drawImage function in Splash.cc in Xpdf 2.x and 3.x before
3.02pl4, and Poppler 0.x, as used in GPdf and kdegraphics KPDF, does
not properly allocate memory, which allows remote attackers to cause a
denial of service (application crash) or possibly execute arbitrary
code via a crafted PDF document that triggers a NULL pointer
dereference or a heap-based buffer overflow (CVE-2009-3604).

Integer overflow in the PSOutputDev::doImageL1Sep function in Xpdf
before 3.02pl4, and Poppler 0.x, as used in kdegraphics KPDF, might
allow remote attackers to execute arbitrary code via a crafted PDF
document that triggers a heap-based buffer overflow (CVE-2009-3606).

Integer overflow in the ObjectStream::ObjectStream function in XRef.cc
in Xpdf 3.x before 3.02pl4 and Poppler before 0.12.1, as used in GPdf,
kdegraphics KPDF, CUPS pdftops, and teTeX, might allow remote
attackers to execute arbitrary code via a crafted PDF document that
triggers a heap-based buffer overflow (CVE-2009-3608).

Integer overflow in the ImageStream::ImageStream function in Stream.cc
in Xpdf before 3.02pl4 and Poppler before 0.12.1, as used in GPdf,
kdegraphics KPDF, and CUPS pdftops, allows remote attackers to cause a
denial of service (application crash) via a crafted PDF document that
triggers a NULL pointer dereference or buffer over-read
(CVE-2009-3609).

This update fixes these vulnerabilities.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xpdf, xpdf-common and / or xpdf-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2008.0", reference:"xpdf-3.02-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xpdf-common-3.02-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xpdf-tools-3.02-8.3mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
