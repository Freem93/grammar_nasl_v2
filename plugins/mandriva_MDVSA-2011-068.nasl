#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:068. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(53327);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/01 00:15:51 $");

  script_xref(name:"MDVSA", value:"2011:068");

  script_name(english:"Mandriva Linux Security Advisory : firefox (MDVSA-2011:068)");
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
"Several invalid HTTPS certificates were placed on the certificate
blacklist to prevent their misuse.

Users on a compromised network could be directed to sites using the
fraudulent certificates and mistake them for the legitimate sites.
This could deceive them into revealing personal information such as
usernames and passwords. It may also deceive users into downloading
malware if they believe it's coming from a trusted site.

The NSS and NSPR packages were updated to the latest versions as well
as the rootcerts packages providing the latest root CA certs from
mozilla as of 2011/03/23.

The firefox packages were updated to the latest 3.6.16 version which
is not vulnerable to this issue.

The mozilla thunderbird 3.1.9 packages were patched with the same fix
as of firefox as a precaution.

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

Additionally, some packages which require so, have been rebuilt and
are being provided as updates."
  );
  # http://blogs.comodo.com/it-security/data-security/the-recent-ra-compromise/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75bf880e"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#firefox3.6.16
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23caafda"
  );
  # https://blog.torproject.org/blog/detecting-certificate-authority-compromises-and-web-browser-collusion
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8fdcaa8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-crawl-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-gui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:devhelp-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:epiphany-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-weave-sync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-xmarks");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-theme-kfirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gda-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:google-gadgets-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:google-gadgets-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:google-gadgets-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devhelp-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devhelp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget-dbus1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget-gtk1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget-js1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget-npapi1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget-qt1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget-webkitjs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget-xdg1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ggadget1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gjs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64google-gadgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64opensc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64opensc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xulrunner1.9.2.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevhelp-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevhelp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget-dbus1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget-gtk1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget-js1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget-npapi1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget-qt1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget-webkitjs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget-xdg1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libggadget1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgjs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgoogle-gadgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopensc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopensc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxulrunner1.9.2.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-plugin-opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nsinstall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"beagle-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-crawl-system-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-doc-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-epiphany-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-evolution-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-gui-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-gui-qt-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-libs-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"devhelp-0.21-3.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"devhelp-plugins-0.21-3.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"epiphany-2.24.3-0.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"epiphany-devel-2.24.3-0.13mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-af-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ar-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-be-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-bg-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-bn-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ca-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-cs-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-cy-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-da-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-de-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-devel-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-el-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-en_GB-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-eo-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-es_AR-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-es_ES-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-et-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-eu-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ext-beagle-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ext-blogrovr-1.1.804-0.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ext-mozvoikko-1.0-0.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ext-scribefire-3.5.1-0.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ext-xmarks-3.5.10-0.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-fi-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-fr-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-fy-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ga_IE-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-gl-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-gu_IN-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-he-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-hi-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-hu-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-id-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-is-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-it-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ja-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ka-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-kn-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ko-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ku-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-lt-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-lv-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-mk-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-mr-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-nb_NO-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-nl-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-nn_NO-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-oc-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-pa_IN-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-pl-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-pt_BR-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-pt_PT-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ro-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ru-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-si-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-sk-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-sl-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-sq-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-sr-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-sv_SE-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-te-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-th-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-theme-kfirefox-0.16-0.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-tr-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-uk-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-zh_CN-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-zh_TW-3.6.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnome-python-extras-2.19.1-20.26mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnome-python-gda-2.19.1-20.26mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnome-python-gda-devel-2.19.1-20.26mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnome-python-gdl-2.19.1-20.26mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnome-python-gtkhtml2-2.19.1-20.26mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnome-python-gtkmozembed-2.19.1-20.26mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnome-python-gtkspell-2.19.1-20.26mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64devhelp-1-devel-0.21-3.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64devhelp-1_0-0.21-3.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64nspr-devel-4.8.7-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64nspr4-4.8.7-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64nss-devel-3.12.9-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64nss-static-devel-3.12.9-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64nss3-3.12.9-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64xulrunner-devel-1.9.2.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64xulrunner1.9.2.16-1.9.2.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libdevhelp-1-devel-0.21-3.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libdevhelp-1_0-0.21-3.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnspr-devel-4.8.7-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnspr4-4.8.7-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnss-devel-3.12.9-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnss-static-devel-3.12.9-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnss3-3.12.9-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libxulrunner-devel-1.9.2.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libxulrunner1.9.2.16-1.9.2.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-beagle-0.3.8-13.35mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ar-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ca-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-cs-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-de-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-el-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-es-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-fi-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-fr-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-hu-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-it-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ja-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ko-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-nb-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-nl-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-pl-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-pt-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-pt_BR-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ru-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-sl-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-sv-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-tr-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-vi-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-zh_CN-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-zh_TW-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-lightning-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nsinstall-3.1.9-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nss-3.12.9-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rootcerts-20110323.00-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rootcerts-java-20110323.00-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xulrunner-1.9.2.16-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"yelp-2.24.0-3.27mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"beagle-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-crawl-system-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-doc-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-evolution-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-gui-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-gui-qt-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"beagle-libs-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-af-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ar-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-be-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-bg-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-bn-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ca-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-cs-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-cy-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-da-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-de-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-devel-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-el-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-en_GB-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-eo-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-es_AR-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-es_ES-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-et-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-eu-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-beagle-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-blogrovr-1.1.804-6.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-mozvoikko-1.0-6.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-plasmanotify-0.3.1-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-r-kiosk-0.7.2-9.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ext-scribefire-3.5.1-0.12mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-fi-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-fr-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-fy-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ga_IE-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-gl-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-gu_IN-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-he-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-hi-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-hu-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-id-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-is-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-it-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ja-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ka-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-kn-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ko-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ku-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-lt-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-lv-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-mk-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-mr-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-nb_NO-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-nl-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-nn_NO-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-oc-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pa_IN-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pl-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pt_BR-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-pt_PT-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ro-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-ru-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-si-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sk-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sl-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sq-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sr-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-sv_SE-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-te-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-th-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-theme-kfirefox-0.16-7.17mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-tr-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-uk-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-zh_CN-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"firefox-zh_TW-3.6.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-extras-2.25.3-10.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gda-2.25.3-10.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gda-devel-2.25.3-10.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gdl-2.25.3-10.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gtkhtml2-2.25.3-10.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gtkmozembed-2.25.3-10.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"gnome-python-gtkspell-2.25.3-10.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"google-gadgets-common-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"google-gadgets-gtk-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"google-gadgets-qt-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget-dbus1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget-gtk1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget-js1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget-npapi1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget-qt1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget-webkitjs0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget-xdg1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ggadget1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64google-gadgets-devel-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nspr-devel-4.8.7-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nspr4-4.8.7-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nss-devel-3.12.9-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nss-static-devel-3.12.9-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nss3-3.12.9-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64opensc-devel-0.11.9-1.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64opensc2-0.11.9-1.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64xulrunner-devel-1.9.2.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64xulrunner1.9.2.16-1.9.2.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget-dbus1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget-gtk1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget-js1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget-npapi1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget-qt1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget-webkitjs0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget-xdg1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libggadget1.0_0-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libgoogle-gadgets-devel-0.11.2-0.13mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnspr-devel-4.8.7-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnspr4-4.8.7-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnss-devel-3.12.9-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnss-static-devel-3.12.9-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnss3-3.12.9-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libopensc-devel-0.11.9-1.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libopensc2-0.11.9-1.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libxulrunner-devel-1.9.2.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libxulrunner1.9.2.16-1.9.2.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-plugin-opensc-0.11.9-1.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-beagle-0.3.9-20.23mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-ar-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-ca-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-cs-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-de-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-el-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-es-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-fi-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-fr-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-hu-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-it-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-ja-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-ko-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-nb-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-nl-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-pl-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-pt-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-pt_BR-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-ru-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-sl-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-sv-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-tr-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-vi-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-zh_CN-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-enigmail-zh_TW-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mozilla-thunderbird-lightning-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nsinstall-3.1.9-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nss-3.12.9-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"opensc-0.11.9-1.18mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"rootcerts-20110323.00-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"rootcerts-java-20110323.00-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"xulrunner-1.9.2.16-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"yelp-2.28.0-1.20mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"beagle-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"beagle-crawl-system-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"beagle-doc-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"beagle-evolution-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"beagle-gui-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"beagle-gui-qt-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"beagle-libs-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-af-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ar-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-be-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-bg-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-bn-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ca-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-cs-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-cy-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-da-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-de-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-devel-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-el-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-en_GB-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-eo-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-es_AR-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-es_ES-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-et-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-eu-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ext-beagle-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ext-blogrovr-1.1.804-13.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ext-mozvoikko-1.0.1-2.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ext-r-kiosk-0.8.1-2.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ext-scribefire-3.5.2-2.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ext-weave-sync-1.1-5.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ext-xmarks-3.6.14-2.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-fi-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-fr-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-fy-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ga_IE-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-gl-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-gu_IN-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-he-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-hi-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-hu-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-id-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-is-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-it-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ja-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ka-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-kn-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ko-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ku-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-lt-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-lv-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-mk-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-mr-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-nb_NO-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-nl-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-nn_NO-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-oc-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pa_IN-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pl-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pt_BR-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pt_PT-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ro-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ru-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-si-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sk-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sl-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sq-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sr-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sv_SE-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-te-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-th-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-tr-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-uk-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-zh_CN-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-zh_TW-3.6.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gjs-0.6-4.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnome-python-extras-2.25.3-18.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnome-python-gda-2.25.3-18.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnome-python-gda-devel-2.25.3-18.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnome-python-gdl-2.25.3-18.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnome-python-gtkhtml2-2.25.3-18.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnome-python-gtkmozembed-2.25.3-18.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gnome-python-gtkspell-2.25.3-18.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gjs-devel-0.6-4.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gjs0-0.6-4.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nspr-devel-4.8.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nspr4-4.8.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nss-devel-3.12.9-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nss-static-devel-3.12.9-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nss3-3.12.9-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xulrunner-devel-1.9.2.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xulrunner1.9.2.16-1.9.2.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgjs-devel-0.6-4.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgjs0-0.6-4.10mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnspr-devel-4.8.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnspr4-4.8.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnss-devel-3.12.9-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnss-static-devel-3.12.9-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnss3-3.12.9-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxulrunner-devel-1.9.2.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxulrunner1.9.2.16-1.9.2.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-beagle-0.3.9-40.13mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ar-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ca-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-cs-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-de-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-el-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-es-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-fi-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-fr-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-hu-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-it-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ja-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ko-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-nb-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-nl-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-pl-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-pt-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-pt_BR-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ru-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-sl-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-sv-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-tr-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-vi-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-zh_CN-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-zh_TW-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-lightning-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nsinstall-3.1.9-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nss-3.12.9-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"rootcerts-20110323.00-1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"rootcerts-java-20110323.00-1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xulrunner-1.9.2.16-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"yelp-2.30.1-4.10mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
