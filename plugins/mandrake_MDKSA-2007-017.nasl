#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:017. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24632);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/31 23:56:40 $");

  script_cve_id("CVE-2006-6719");
  script_xref(name:"MDKSA", value:"2007:017");

  script_name(english:"Mandrake Linux Security Advisory : wget (MDKSA-2007:017)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ftp_syst function in ftp-basic.c in Free Software Foundation (FSF)
GNU wget 1.10.2 allows remote attackers to cause a denial of service
(application crash) via a malicious FTP server with a large number of
blank 220 responses to the SYST command.

The updated packages have been patched to correct this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected wget package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"wget-1.10-1.2.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", reference:"wget-1.10.2-3.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
