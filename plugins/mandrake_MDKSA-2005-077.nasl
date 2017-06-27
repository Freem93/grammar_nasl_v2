#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:077. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(18107);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-0866");
  script_xref(name:"MDKSA", value:"2005:077");

  script_name(english:"Mandrake Linux Security Advisory : cdrecord (MDKSA-2005:077)");
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
"Javier Fernandez-Sanguino Pena discovered that cdrecord created
temporary files in an insecure manner if DEBUG was enabled in
/etc/cdrecord/rscsi. If the default value was used (which stored the
debug output file in /tmp), a symbolic link attack could be used to
create or overwrite arbitrary files with the privileges of the user
invoking cdrecord. Please note that by default this configuration file
does not exist in Mandriva Linux so unless you create it and enable
DEBUG, this does not affect you.

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/291376"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cdrecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cdrecord-cdda2wav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cdrecord-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cdrecord-isotools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cdrecord-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mkisofs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"cdrecord-2.01-0.a28.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"cdrecord-cdda2wav-2.01-0.a28.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"cdrecord-devel-2.01-0.a28.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mkisofs-2.01-0.a28.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"cdrecord-2.01-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"cdrecord-cdda2wav-2.01-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"cdrecord-devel-2.01-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"cdrecord-isotools-2.01-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"cdrecord-vanilla-2.01-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mkisofs-2.01-1.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"cdrecord-2.01.01-0.a01.6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"cdrecord-cdda2wav-2.01.01-0.a01.6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"cdrecord-devel-2.01.01-0.a01.6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"cdrecord-isotools-2.01.01-0.a01.6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"cdrecord-vanilla-2.01.01-0.a01.6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"mkisofs-2.01.01-0.a01.6.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
