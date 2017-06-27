#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:117. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66129);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/25 11:41:40 $");

  script_cve_id("CVE-2011-4944");
  script_bugtraq_id(52732);
  script_xref(name:"MDVSA", value:"2013:117");
  script_xref(name:"MGASA", value:"2012-0170");

  script_name(english:"Mandriva Linux Security Advisory : python (MDVSA-2013:117)");
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
"Updated python packages fix security vulnerabilities :

A race condition was found in the way the Python distutils module set
file permissions during the creation of the .pypirc file. If a local
user had access to the home directory of another user who is running
distutils, they could use this flaw to gain access to that user's
.pypirc file, which can contain usernames and passwords for code
repositories (CVE-2011-4944).

Additionally, python has been built against the system expat and ffi
libraries, to avoid any future issues with those (mitigates
CVE-2012-0876 for expat)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.mageia.org/en/Support/Advisories/MGAA-2012-0160"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter-apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64python-devel-2.7.3-4.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64python2.7-2.7.3-4.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-2.7.3-4.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"python-docs-2.7.3-4.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tkinter-2.7.3-4.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tkinter-apps-2.7.3-4.3.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
