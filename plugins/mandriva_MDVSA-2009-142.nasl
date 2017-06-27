#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:142. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(39552);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2007-2721", "CVE-2008-3520", "CVE-2008-3521", "CVE-2008-3522");
  script_bugtraq_id(31470);
  script_xref(name:"MDVSA", value:"2009:142-1");

  script_name(english:"Mandriva Linux Security Advisory : jasper (MDVSA-2009:142-1)");
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
"Multiple security vulnerabilities has been identified and fixed in
jasper :

The jpc_qcx_getcompparms function in jpc/jpc_cs.c for the JasPer
JPEG-2000 library (libjasper) before 1.900 allows remote user-assisted
attackers to cause a denial of service (crash) and possibly corrupt
the heap via malformed image files, as originally demonstrated using
imagemagick convert (CVE-2007-2721).

Multiple integer overflows in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via a crafted
image file, related to integer multiplication for memory allocation
(CVE-2008-3520).

The jas_stream_tmpfile function in libjasper/base/jas_stream.c in
JasPer 1.900.1 allows local users to overwrite arbitrary files via a
symlink attack on a tmp.XXXXXXXXXX temporary file (CVE-2008-3521).

Buffer overflow in the jas_stream_printf function in
libjasper/base/jas_stream.c in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via vectors
related to the mif_hdr_put function and use of vsprintf
(CVE-2008-3522).

The updated packages have been patched to prevent this.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64jasper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64jasper1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64jasper1-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libjasper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libjasper1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libjasper1-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/28");
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
if (rpm_check(release:"MDK2008.0", reference:"jasper-1.900.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64jasper1-1.900.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64jasper1-devel-1.900.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64jasper1-static-devel-1.900.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libjasper1-1.900.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libjasper1-devel-1.900.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libjasper1-static-devel-1.900.1-2.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
