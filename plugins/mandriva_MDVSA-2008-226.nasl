#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:226. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38018);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_xref(name:"MDVSA", value:"2008:226");

  script_name(english:"Mandriva Linux Security Advisory : ruby (MDVSA-2008:226)");
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
"A denial of service condition was found in Ruby's regular expression
engine. If a Ruby script tried to process a large amount of data via a
regular expression, it could cause Ruby to enter an infinite loop and
crash (CVE-2008-3443).

A number of flaws were found in Ruby that could allow an attacker to
create a carefully crafted script that could allow for the bypass of
certain safe-level restrictions (CVE-2008-3655).

A denial of service vulnerability was found in Ruby's HTTP server
toolkit, WEBrick. A remote attacker could send a specially crafted
HTTP request to a WEBrick server that would cause it to use an
excessive amount of CPU time (CVE-2008-3656).

An insufficient taintness check issue was found in Ruby's DL module, a
module that provides direct access to the C language functions. This
flaw could be used by an attacker to bypass intended safe-level
restrictions by calling external C functions with the arguments from
an untrusted tainted input (CVE-2008-3657).

A denial of service condition in Ruby's XML document parsing module
(REXML) could cause a Ruby application using the REXML module to use
an excessive amount of CPU and memory via XML documents with large XML
entitity definitions recursion (CVE-2008-3790).

The Ruby DNS resolver library used predictable transaction IDs and a
fixed source port when sending DNS requests. This could be used by a
remote attacker to spoof a malicious reply to a DNS query
(CVE-2008-3905).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"MDK2008.0", reference:"ruby-1.8.6-5.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-devel-1.8.6-5.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-doc-1.8.6-5.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-tk-1.8.6-5.3mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"ruby-1.8.6-9p114.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"ruby-devel-1.8.6-9p114.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"ruby-doc-1.8.6-9p114.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"ruby-tk-1.8.6-9p114.2mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
