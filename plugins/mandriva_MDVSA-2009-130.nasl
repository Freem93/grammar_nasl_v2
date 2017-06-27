#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:130. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(39322);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/01 00:06:03 $");

  script_cve_id("CVE-2009-1932");
  script_xref(name:"MDVSA", value:"2009:130-1");

  script_name(english:"Mandriva Linux Security Advisory : gstreamer0.10-plugins-good (MDVSA-2009:130-1)");
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
"Multiple integer overflows in the (1) user_info_callback, (2)
user_endrow_callback, and (3) gst_pngdec_task functions
(ext/libpng/gstpngdec.c) in GStreamer Good Plug-ins (aka
gst-plugins-good or gstreamer-plugins-good) 0.10.15 allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via a crafted PNG file, which triggers a buffer overflow
(CVE-2009-1932).

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-aalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-caca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-raw1394");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-speex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gstreamer0.10-wavpack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-aalib-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-caca-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-dv-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-esound-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-flac-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-plugins-good-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-raw1394-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-speex-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gstreamer0.10-wavpack-0.10.6-3.3mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
