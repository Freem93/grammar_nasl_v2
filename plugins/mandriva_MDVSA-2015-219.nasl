#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:219. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(83243);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/05 14:25:54 $");

  script_cve_id("CVE-2015-3143", "CVE-2015-3145", "CVE-2015-3148");
  script_xref(name:"MDVSA", value:"2015:219");

  script_name(english:"Mandriva Linux Security Advisory : curl (MDVSA-2015:219)");
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
"Updated curl packages fix security vulnerabilities :

NTLM-authenticated connections could be wrongly reused for requests
without any credentials set, leading to HTTP requests being sent over
the connection authenticated as a different user (CVE-2015-3143).

When parsing HTTP cookies, if the parsed cookie's path element
consists of a single double-quote, libcurl would try to write to an
invalid heap memory address. This could allow remote attackers to
cause a denial of service (crash) (CVE-2015-3145).

When doing HTTP requests using the Negotiate authentication method
along with NTLM, the connection used would not be marked as
authenticated, making it possible to reuse it and send requests for
one user over the connection authenticated as a different user
(CVE-2015-3148)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0179.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:curl-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64curl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64curl4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"curl-7.34.0-3.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"curl-examples-7.34.0-3.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64curl-devel-7.34.0-3.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64curl4-7.34.0-3.2.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
