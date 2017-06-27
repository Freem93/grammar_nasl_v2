#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:082. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66096);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:20:15 $");

  script_cve_id("CVE-2012-3236", "CVE-2012-3403", "CVE-2012-3481", "CVE-2012-5576");
  script_bugtraq_id(54246, 55101, 56647);
  script_xref(name:"MDVSA", value:"2013:082");
  script_xref(name:"MGASA", value:"2012-0236");
  script_xref(name:"MGASA", value:"2012-0286");
  script_xref(name:"MGASA", value:"2012-0360");

  script_name(english:"Mandriva Linux Security Advisory : gimp (MDVSA-2013:082)");
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
"Updated gimp packages fix security vulnerabilities :

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the GIMP's GIF image format plug-in. An attacker could create
a specially crafted GIF image file that, when opened, could cause the
GIF plug-in to crash or, potentially, execute arbitrary code with the
privileges of the user running the GIMP (CVE-2012-3481).

A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL
file format plug-in. An attacker could create a specially crafted KiSS
palette file that, when opened, could cause the CEL plug-in to crash
or, potentially, execute arbitrary code with the privileges of the
user running the GIMP (CVE-2012-3403).

fits-io.c in GIMP before 2.8.1 allows remote attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a malformed XTENSION header of a .fit file, as demonstrated using a
long string. (CVE-2012-3236)

GIMP 2.8.2 and earlier is vulnerable to memory corruption when reading
XWD files, which could lead even to arbitrary code execution
(CVE-2012-5576).

Additionally it fixes partial translations in several languages.

This gimp update provides the stable maintenance release 2.8.2 which
fixes the above security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gimp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimp2.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimp2.0_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"gimp-2.8.2-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"gimp-python-2.8.2-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64gimp2.0-devel-2.8.2-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64gimp2.0_0-2.8.2-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
