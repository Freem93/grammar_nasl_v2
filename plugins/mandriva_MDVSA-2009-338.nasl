#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:338. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48162);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986", "CVE-2009-3987");
  script_bugtraq_id(37361, 37362, 37364, 37365, 37366, 37367, 37368, 37369, 37370);
  script_xref(name:"MDVSA", value:"2009:338");

  script_name(english:"Mandriva Linux Security Advisory : firefox (MDVSA-2009:338)");
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
"Security issues were identified and fixed in firefox 3.5.x :

liboggplay in Mozilla Firefox 3.5.x before 3.5.6 and SeaMonkey before
2.0.1 might allow context-dependent attackers to cause a denial of
service (application crash) or execute arbitrary code via unspecified
vectors, related to memory safety issues. (CVE-2009-3388)

Integer overflow in libtheora in Xiph.Org Theora before 1.1, as used
in Mozilla Firefox 3.5 before 3.5.6 and SeaMonkey before 2.0.1, allows
remote attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a video with large dimensions
(CVE-2009-3389).

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 3.0.16 and 3.5.x before 3.5.6, SeaMonkey before 2.0.1,
and Thunderbird allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors (CVE-2009-3979).

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 3.5.x before 3.5.6, SeaMonkey before 2.0.1, and Thunderbird
allow remote attackers to cause a denial of service (memory corruption
and application crash) or possibly execute arbitrary code via unknown
vectors (CVE-2009-3980).

Multiple unspecified vulnerabilities in the JavaScript engine in
Mozilla Firefox 3.5.x before 3.5.6, SeaMonkey before 2.0.1, and
Thunderbird allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors (CVE-2009-3982).

Mozilla Firefox before 3.0.16 and 3.5.x before 3.5.6, and SeaMonkey
before 2.0.1, allows remote attackers to send authenticated requests
to arbitrary applications by replaying the NTLM credentials of a
browser user (CVE-2009-3983).

Mozilla Firefox before 3.0.16 and 3.5.x before 3.5.6, and SeaMonkey
before 2.0.1, allows remote attackers to spoof an SSL indicator for an
http URL or a file URL by setting document.location to an https URL
corresponding to a site that responds with a No Content (aka 204)
status code and an empty body (CVE-2009-3984).

Mozilla Firefox before 3.0.16 and 3.5.x before 3.5.6, and SeaMonkey
before 2.0.1, allows remote attackers to associate spoofed content
with an invalid URL by setting document.location to this URL, and then
writing arbitrary web script or HTML to the associated blank document,
a related issue to CVE-2009-2654 (CVE-2009-3985).

Mozilla Firefox before 3.0.16 and 3.5.x before 3.5.6, and SeaMonkey
before 2.0.1, allows remote attackers to execute arbitrary JavaScript
with chrome privileges by leveraging a reference to a chrome window
from a content window, related to the window.opener property
(CVE-2009-3986).

The GeckoActiveXObject function in Mozilla Firefox before 3.0.16 and
3.5.x before 3.5.6, and SeaMonkey before 2.0.1, generates different
exception messages depending on whether the referenced COM object is
listed in the registry, which allows remote attackers to obtain
potentially sensitive information about installed software by making
multiple calls that specify the ProgID values of different COM objects
(CVE-2009-3987).

Additionally, some packages which require so, have been rebuilt and
are being provided as updates."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox35.html#firefox3.5.6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca8b7967"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-crawl-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-gui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-blogrovr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-plasmanotify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-r-kiosk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-scribefire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-theme-kde4ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gda-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64opensc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64opensc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xulrunner1.9.1.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopensc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopensc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxulrunner1.9.1.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-plugin-opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-xpcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", reference:"beagle-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-crawl-system-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-doc-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-evolution-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-gui-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-gui-qt-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-libs-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-af-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ar-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-be-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-bg-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-bn-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ca-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-cs-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-cy-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-da-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-de-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-devel-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-el-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-en_GB-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-eo-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-es_AR-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-es_ES-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-et-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-eu-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-beagle-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-blogrovr-1.1.804-6.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-mozvoikko-1.0-6.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-plasmanotify-0.3.0-6.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-r-kiosk-0.7.2-9.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-scribefire-3.4.5-1.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-fi-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-fr-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-fy-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ga_IE-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-gl-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-gu_IN-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-he-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-hi-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-hu-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-id-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-is-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-it-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ja-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ka-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-kn-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ko-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ku-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-lt-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-lv-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-mk-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-mn-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-mr-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-nb_NO-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-nl-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-nn_NO-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-oc-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pa_IN-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pl-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pt_BR-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pt_PT-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ro-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ru-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-si-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sk-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sl-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sq-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sr-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sv_SE-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-te-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-th-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-theme-kde4ff-0.14-18.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-tr-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-uk-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-zh_CN-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-zh_TW-3.5.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-extras-2.25.3-10.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gda-2.25.3-10.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gda-devel-2.25.3-10.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gdl-2.25.3-10.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gtkhtml2-2.25.3-10.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gtkmozembed-2.25.3-10.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gtkspell-2.25.3-10.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64opensc-devel-0.11.9-1.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64opensc2-0.11.9-1.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64xulrunner-devel-1.9.1.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64xulrunner1.9.1.6-1.9.1.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libopensc-devel-0.11.9-1.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libopensc2-0.11.9-1.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libxulrunner-devel-1.9.1.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libxulrunner1.9.1.6-1.9.1.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-plugin-opensc-0.11.9-1.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-beagle-0.3.9-19.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"opensc-0.11.9-1.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"python-xpcom-1.9.1.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"xulrunner-1.9.1.6-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"yelp-2.28.0-1.3mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
