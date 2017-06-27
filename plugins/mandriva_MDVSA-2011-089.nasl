#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:089. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(54290);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/03/07 17:48:16 $");

  script_cve_id(
    "CVE-2009-4636",
    "CVE-2010-3429",
    "CVE-2010-4704",
    "CVE-2011-0722",
    "CVE-2011-0723"
  );
  script_bugtraq_id(
    36465,
    43546,
    46294,
    47149,
    47151
  );
  script_osvdb_id(
    58508,
    68269,
    70650,
    72574,
    72578
  );
  script_xref(name:"MDVSA", value:"2011:089");

  script_name(english:"Mandriva Linux Security Advisory : mplayer (MDVSA-2011:089)");
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
"Multiple vulnerabilities have been identified and fixed in mplayer :

FFmpeg 0.5 allows remote attackers to cause a denial of service (hang)
via a crafted file that triggers an infinite loop. (CVE-2009-4636)

flicvideo.c in libavcodec 0.6 and earlier in FFmpeg, as used in
MPlayer and other products, allows remote attackers to execute
arbitrary code via a crafted flic file, related to an arbitrary offset
dereference vulnerability. (CVE-2010-3429)

libavcodec/vorbis_dec.c in the Vorbis decoder in FFmpeg 0.6.1 and
earlier allows remote attackers to cause a denial of service
(application crash) via a crafted .ogg file, related to the
vorbis_floor0_decode function. (CVE-2010-4704)

Fix heap corruption crashes (CVE-2011-0722)

Fix invalid reads in VC-1 decoding (CVE-2011-0723)

And several additional vulnerabilities originally discovered by Google
Chrome developers were also fixed with this advisory.

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mencoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"mencoder-1.0-1.rc4.0.r31086.3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mplayer-1.0-1.rc4.0.r31086.3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mplayer-doc-1.0-1.rc4.0.r31086.3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mplayer-gui-1.0-1.rc4.0.r31086.3.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
