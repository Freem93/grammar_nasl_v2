#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:035. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37493);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/30 13:45:24 $");

  script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");
  script_bugtraq_id(33405);
  script_xref(name:"MDVSA", value:"2009:035");

  script_name(english:"Mandriva Linux Security Advisory : gstreamer0.10-plugins-good (MDVSA-2009:035)");
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
"Security vulnerabilities have been discovered and corrected in
gstreamer0.10-plugins-good, might allow remote attackers to execute
arbitrary code via a malformed QuickTime media file (CVE-2009-0386,
CVE-2009-0387, CVE-2009-0397).

The updated packages have been patched to prevent this."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-aalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-caca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-raw1394");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-soup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-speex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-wavpack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-aalib-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-caca-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-dv-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-esound-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-flac-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-plugins-good-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-raw1394-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-speex-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-wavpack-0.10.6-3.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-aalib-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-caca-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-dv-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-esound-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-flac-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-plugins-good-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-raw1394-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-speex-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"gstreamer0.10-wavpack-0.10.7-3.2mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-aalib-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-caca-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-dv-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-esound-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-flac-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-plugins-good-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-pulse-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-raw1394-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-soup-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-speex-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gstreamer0.10-wavpack-0.10.10-2.1mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
