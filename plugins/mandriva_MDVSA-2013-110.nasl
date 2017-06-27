#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:110. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66122);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/16 19:20:15 $");

  script_cve_id("CVE-2009-5030", "CVE-2012-3358", "CVE-2012-3535");
  script_bugtraq_id(53012, 54373, 55214);
  script_xref(name:"MDVSA", value:"2013:110");
  script_xref(name:"MGASA", value:"2012-0152");
  script_xref(name:"MGASA", value:"2012-0166");
  script_xref(name:"MGASA", value:"2012-0274");

  script_name(english:"Mandriva Linux Security Advisory : openjpeg (MDVSA-2013:110)");
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
"Updated openjpeg packages fix security vulnerability :

An out-of heap-based buffer bounds read and write flaw, leading to
invalid free, was found in the way a tile coder / decoder (TCD)
implementation of OpenJPEG, an open source JPEG 2000 codec written in
C language, performed releasing of previously allocated memory for the
TCD encoder handle by processing certain Gray16 TIFF images. A remote
attacker could provide a specially crafted TIFF image file, which once
converted into the JPEG 2000 file format with an application linked
against OpenJPEG (such as 'image_to_j2k'), would lead to that
application crash, or, potentially arbitrary code execution with the
privileges of the user running the application (CVE-2009-5030).

An input validation flaw, leading to a heap-based buffer overflow, was
found in the way OpenJPEG handled the tile number and size in an image
tile header. A remote attacker could provide a specially crafted image
file that, when decoded using an application linked against OpenJPEG,
would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the application
(CVE-2012-3358).

It was found that OpenJPEG failed to sanity-check an image header
field before using it. A remote attacker could provide a specially
crafted image file that could cause an application linked against
OpenJPEG to crash or, possibly, execute arbitrary code
(CVE-2012-3535)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected lib64openjpeg-devel, lib64openjpeg1 and / or
openjpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openjpeg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openjpeg-devel-1.5.0-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openjpeg1-1.5.0-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openjpeg-1.5.0-2.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
