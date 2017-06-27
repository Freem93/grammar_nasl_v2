#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:203. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(27614);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id(
    "CVE-2007-1320",
    "CVE-2007-1321",
    "CVE-2007-3919",
    "CVE-2007-4993",
    "CVE-2007-5729",
    "CVE-2007-5730"
  );
  script_bugtraq_id(23731);
  script_osvdb_id(
    35494,
    35495,
    41340,
    41342,
    41343,
    42985,
    42986
  );
  script_xref(name:"MDKSA", value:"2007:203");

  script_name(english:"Mandrake Linux Security Advisory : xen (MDKSA-2007:203)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered a heap overflow flaw during video-to-video
copy operations in the Cirrus VGA extension code that is used in Xen.
A malicious local administrator of a guest domain could potentially
trigger this flaw and execute arbitrary code outside of the domain
(CVE-2007-1320).

Tavis Ormandy also discovered insufficient input validation leading to
a heap overflow in the NE2000 network driver in Xen. If the driver is
in use, a malicious local administrator of a guest domain could
potentially trigger this flaw and execute arbitrary code outside of
the domain (CVE-2007-1321, CVE-2007-5729, CVE-2007-5730).

Steve Kemp found that xen-utils used insecure temporary files within
the xenmon tool that could allow local users to truncate arbitrary
files (CVE-2007-3919).

Joris van Rantwijk discovered a flaw in Pygrub, which is used as a
boot loader for guest domains. A malicious local administrator of a
guest domain could create a carefully-crafted grub.conf file which
could trigger the execution of arbitrary code outside of that domain
(CVE-2007-4993).

Updated packages have been patched to prevent these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 59, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"xen-3.0.3-0.20060703.3.1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"xen-3.0.3-0.20060703.5.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
