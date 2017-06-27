#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:209. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20442);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2335", "CVE-2005-3088");
  script_xref(name:"MDKSA", value:"2005:209");

  script_name(english:"Mandrake Linux Security Advisory : fetchmail (MDKSA-2005:209)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Thomas Wolff and Miloslav Trmac discovered a race condition in the
fetchmailconf program. fetchmailconf would create the initial output
configuration file with insecure permissions and only after writing
would it change permissions to be more restrictive. During that time,
passwords and other data could be exposed to other users on the system
unless the user used a more restrictive umask setting.

As well, the Mandriva Linux 2006 packages did not contain the patch
that corrected the issues fixed in MDKSA-2005:126, namely a buffer
overflow in fetchmail's POP3 client (CVE-2005-2355).

The updated packages have been patched to address this issue, and the
Mandriva 2006 packages have also been patched to correct
CVE-2005-2355."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected fetchmail, fetchmail-daemon and / or fetchmailconf
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmail-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fetchmailconf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"fetchmail-6.2.5-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"fetchmail-daemon-6.2.5-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"fetchmailconf-6.2.5-5.2.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"fetchmail-6.2.5-10.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"fetchmail-daemon-6.2.5-10.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"fetchmailconf-6.2.5-10.3.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"fetchmail-6.2.5-11.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"fetchmail-daemon-6.2.5-11.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"fetchmailconf-6.2.5-11.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
