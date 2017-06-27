#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:079. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48180);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/06/01 00:11:07 $");

  script_cve_id("CVE-2010-1155", "CVE-2010-1156");
  script_xref(name:"MDVSA", value:"2010:079");

  script_name(english:"Mandriva Linux Security Advisory : irssi (MDVSA-2010:079)");
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
"Multiple vulnerabilities has been found and corrected in irssi :

Irssi before 0.8.15, when SSL is used, does not verify that the server
hostname matches a domain name in the subject's Common Name (CN) field
or a Subject Alternative Name field of the X.509 certificate, which
allows man-in-the-middle attackers to spoof IRC servers via an
arbitrary certificate (CVE-2010-1155).

core/nicklist.c in Irssi before 0.8.15 allows remote attackers to
cause a denial of service (NULL pointer dereference and application
crash) via vectors related to an attempted fuzzy nick match at the
instant that a victim leaves a channel (CVE-2010-1156).

Additionally the updated packages disables the SSLv2 protocol and
enables the SSLv3 and TLSv1 protocols for added security.

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected irssi, irssi-devel and / or irssi-perl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:irssi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:irssi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:irssi-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.1", reference:"irssi-0.8.12-4.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"irssi-devel-0.8.12-4.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"irssi-perl-0.8.12-4.2mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"irssi-0.8.14-2.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"irssi-devel-0.8.14-2.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"irssi-perl-0.8.14-2.1mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
