#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:046. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66060);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:14:49 $");

  script_cve_id("CVE-2012-2088", "CVE-2012-2113", "CVE-2012-3401", "CVE-2012-4447", "CVE-2012-4564", "CVE-2012-5581");
  script_bugtraq_id(54076, 54270, 54601, 55673, 56372, 56715);
  script_xref(name:"MDVSA", value:"2013:046");
  script_xref(name:"MGASA", value:"2012-0137");
  script_xref(name:"MGASA", value:"2012-0181");
  script_xref(name:"MGASA", value:"2012-0317");
  script_xref(name:"MGASA", value:"2012-0332");
  script_xref(name:"MGASA", value:"2012-0355");

  script_name(english:"Mandriva Linux Security Advisory : libtiff (MDVSA-2013:046)");
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
"Updated libtiff packages fix security vulnerabilities :

libtiff did not properly convert between signed and unsigned integer
values, leading to a buffer overflow. An attacker could use this flaw
to create a specially crafted TIFF file that, when opened, would cause
an application linked against libtiff to crash or, possibly, execute
arbitrary code (CVE-2012-2088).

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the tiff2pdf tool. An attacker could use
these flaws to create a specially crafted TIFF file that would cause
tiff2pdf to crash or, possibly, execute arbitrary code
(CVE-2012-2113).

Huzaifa Sidhpurwala discovered that the tiff2pdf utility incorrectly
handled certain malformed TIFF images. If a user or automated system
were tricked into opening a specially crafted TIFF image, a remote
attacker could crash the application, leading to a denial of service,
or possibly execute arbitrary code with user privileges
(CVE-2012-3401).

It was discovered that a buffer overflow in libtiff's parsing of files
using PixarLog compression could lead to the execution of arbitrary
code (CVE-2012-4447).

ppm2tiff does not check the return value of the TIFFScanlineSize
function, which allows remote attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a crafted PPM image
that triggers an integer overflow, a zero-memory allocation, and a
heap-based buffer overflow (CVE-2012-4564).

It was discovered that LibTIFF incorrectly handled certain malformed
images using the DOTRANGE tag. If a user or automated system were
tricked into opening a specially crafted TIFF image, a remote attacker
could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges (CVE-2012-5581)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64tiff-devel-4.0.1-3.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64tiff-static-devel-4.0.1-3.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64tiff5-4.0.1-3.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"libtiff-progs-4.0.1-3.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
