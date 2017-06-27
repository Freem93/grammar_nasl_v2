#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:346. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43613);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id(
    "CVE-2009-0146",
    "CVE-2009-0147",
    "CVE-2009-0165",
    "CVE-2009-0166",
    "CVE-2009-0689",
    "CVE-2009-0799",
    "CVE-2009-0800",
    "CVE-2009-1179",
    "CVE-2009-1180",
    "CVE-2009-1181",
    "CVE-2009-1182",
    "CVE-2009-1183",
    "CVE-2009-1687",
    "CVE-2009-1690",
    "CVE-2009-1698",
    "CVE-2009-1725",
    "CVE-2009-2537",
    "CVE-2009-2702",
    "CVE-2009-3603",
    "CVE-2009-3604",
    "CVE-2009-3605",
    "CVE-2009-3606",
    "CVE-2009-3608",
    "CVE-2009-3609"
  );
  script_bugtraq_id(
    34568,
    35271,
    35309,
    35318,
    35446,
    35510,
    36229,
    36703
  );
  script_osvdb_id(
    54465,
    54466,
    54467,
    54468,
    54469,
    54470,
    54471,
    54472,
    54473,
    54476,
    54477,
    54478,
    54479,
    54480,
    54481,
    54482,
    54483,
    54484,
    54485,
    54486,
    54487,
    54488,
    54489,
    54495,
    54496,
    54497,
    55414,
    55417,
    55418,
    55739,
    56255,
    57746,
    59175,
    59176,
    59177,
    59178,
    59179,
    59180,
    59181,
    59182,
    59183,
    59825,
    61187
  );
  script_xref(name:"MDVSA", value:"2009:346");

  script_name(english:"Mandriva Linux Security Advisory : kde (MDVSA-2009:346)");
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
"Mandriva Linux 2008.0 was released with KDE version 3.5.7.

This update upgrades KDE in Mandriva Linux 2008.0 to version 3.5.10,
which brings many bugfixes, overall improvements and many security
fixes.

kdegraphics contains security fixes for
CVE-2009-3603,3604,3605,3606,3608,3609,0146,0147,0165,0166,0799,0800,1
179,1180,1181,1182,1183

kdelibs contains security fixes for
CVE-2009-0689,1687,1690,1698,2702,1725,2537

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/56485"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 119, 189, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:free-kde-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fribidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:htdig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:htdig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:htdig-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde-i18n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde3-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaccessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaccessibility-kttsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaccessibility-kttsd-akode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-akregator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-atlantik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-kaddressbook-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-kfile-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-kicker-applets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-konq-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-konqimagegallery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-metabar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-renamedlg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons-searchbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork-icons-theme-Locolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork-icons-theme-ikons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork-icons-theme-kdeclassic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork-icons-theme-kids");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork-icons-theme-slick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork-screensavers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork-screensavers-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdeprintfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-ksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-session-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kcolorchooser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kcoloredit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kiconedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kuickshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-mrmlsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-juk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-kaboodle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-kaudiocreator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-kmid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-kmix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-krec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-kscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-noatun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kdict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kopete-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kppp-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-ksirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-ktalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kwifimanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-akregator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kaddressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kandy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-karm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kitchensync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-knode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-knotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kontact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-korn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-ktnef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-wizards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-cervisia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-kbabel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-kcachegrind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-kompare");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-po2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-umbrello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdetoys-kweather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-ark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kcharselect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kdessh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kfloppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kgpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-khexedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kjots");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-klaptop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kmilo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-ksim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-ktimer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-kwalletmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-superkaramba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdevelop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdevelop-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdewebdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdewebdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdewebdev-kfilereplace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdewebdev-kommander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdewebdev-quanta-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kjsembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ksig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64arts1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64arts1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64fribidi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64fribidi-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64fribidi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gwsoap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeaccessibility1-kttsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeaccessibility1-kttsd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeedu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeedu1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegames1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegames1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kghostview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kooka-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kpovmodeler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-ksvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdemultimedia1-arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdemultimedia1-arts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdemultimedia1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdemultimedia1-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdemultimedia1-noatun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdemultimedia1-noatun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-kaddressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-kitchensync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-kontact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-ktnef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-qopensync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdesdk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdesdk1-cervisia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdesdk1-kbabel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdetoys1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdetoys1-kweather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeutils1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeutils1-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeutils1-khexedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeutils1-klaptop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeutils1-kmilo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeutils1-ksim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdevelop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdevelop3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdewebdev0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdewebdev0-kommander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kjsembed1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kjsembed1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smokekde1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smokeqt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libarts1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libarts1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfribidi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfribidi-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfribidi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgwsoap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeaccessibility1-kttsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeaccessibility1-kttsd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeedu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeedu1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegames1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegames1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kghostview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kooka-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kpovmodeler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-ksvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdemultimedia1-arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdemultimedia1-arts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdemultimedia1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdemultimedia1-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdemultimedia1-noatun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdemultimedia1-noatun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-kaddressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-kitchensync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-kontact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-ktnef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-qopensync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdesdk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdesdk1-cervisia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdesdk1-kbabel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdetoys1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdetoys1-kweather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeutils1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeutils1-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeutils1-khexedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeutils1-klaptop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeutils1-kmilo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeutils1-ksim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdevelop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdevelop3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdewebdev0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdewebdev0-kommander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkjsembed1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkjsembed1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmokekde1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmokeqt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lisa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mandriva-kde-config-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mandriva-kde-translation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mandriva-kdm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss_mdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:one-kde-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-DCOP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:powerpack-kde-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:smoke-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:task-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:task-kde-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xsettings-kde");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/30");
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
if (rpm_check(release:"MDK2008.0", reference:"arts-1.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"free-kde-config-2008.0-29.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"fribidi-0.19.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"htdig-3.2.0-1.12mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"htdig-devel-3.2.0-1.12mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"htdig-web-3.2.0-1.12mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-af-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ar-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-az-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-be-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-bg-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-bn-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-br-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-bs-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ca-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-cs-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-csb-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-cy-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-da-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-de-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-el-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-en_GB-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-eo-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-es-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-eu-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-fa-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-fi-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-fr-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-fy-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ga-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-gl-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-he-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-hi-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-hr-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-hu-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-is-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-it-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ja-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-kk-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-km-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ko-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-lt-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-lv-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-mk-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-mn-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ms-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-nb-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-nds-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-nl-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-nn-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-pa-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-pl-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-pt-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-pt_BR-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ro-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ru-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-rw-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-se-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-sk-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-sl-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-sr-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ss-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-sv-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-ta-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-te-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-tg-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-th-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-tr-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-uk-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-uz-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-vi-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-wa-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-zh_CN-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde-i18n-zh_TW-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kde3-macros-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaccessibility-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaccessibility-kttsd-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaccessibility-kttsd-akode-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-akregator-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-atlantik-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-kaddressbook-plugins-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-kate-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-kfile-plugins-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-kicker-applets-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-knewsticker-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-konq-plugins-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-konqimagegallery-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-metabar-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-renamedlg-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeaddons-searchbar-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-icons-theme-Locolor-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-icons-theme-ikons-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-icons-theme-kdeclassic-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-icons-theme-kids-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-icons-theme-slick-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-screensavers-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeartwork-screensavers-gl-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-common-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-devel-doc-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kate-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kdeprintfax-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kdm-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kmenuedit-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-konsole-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-ksysguard-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-nsplugins-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-progs-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-session-plugins-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeedu-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegames-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-common-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kcolorchooser-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kcoloredit-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kdvi-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kfax-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kghostview-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kiconedit-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kolourpaint-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kooka-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kpdf-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kpovmodeler-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kruler-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-ksnapshot-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-ksvg-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kuickshow-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-kview-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdegraphics-mrmlsearch-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdelibs-common-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdelibs-devel-doc-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-arts-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-juk-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-kaboodle-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-kaudiocreator-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-kmid-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-kmix-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-krec-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-kscd-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdemultimedia-noatun-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-kdict-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-kget-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-knewsticker-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-kopete-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-kopete-latex-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-kppp-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-kppp-provider-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-krfb-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-ksirc-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-ktalk-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdenetwork-kwifimanager-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-akregator-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-devel-doc-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-kaddressbook-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-kandy-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-karm-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-kitchensync-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-kmail-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-knode-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-knotes-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-kontact-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-korganizer-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-korn-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-kpilot-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-ktnef-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdepim-wizards-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-cervisia-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-kbabel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-kcachegrind-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-kompare-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-po2xml-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdesdk-umbrello-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdetoys-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdetoys-kweather-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-ark-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kcalc-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kcharselect-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kdessh-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kdf-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kedit-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kfloppy-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kgpg-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-khexedit-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kjots-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-klaptop-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kmilo-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-ksim-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-ktimer-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-kwalletmanager-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdeutils-superkaramba-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdevelop-3.5.4-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdevelop-doc-3.5.4-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdewebdev-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdewebdev-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdewebdev-kfilereplace-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdewebdev-kommander-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdewebdev-quanta-doc-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kjsembed-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ksig-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64arts1-1.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64arts1-devel-1.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64fribidi-devel-0.19.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64fribidi-static-devel-0.19.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64fribidi0-0.19.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64gwsoap0-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeaccessibility1-kttsd-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeaccessibility1-kttsd-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdebase4-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdebase4-devel-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdebase4-kate-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdecore4-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdecore4-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeedu-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeedu1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegames1-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegames1-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-common-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-common-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kghostview-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kghostview-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kooka-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kooka-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kpovmodeler-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kpovmodeler-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-ksvg-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-ksvg-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kview-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdegraphics0-kview-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdemultimedia1-arts-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdemultimedia1-arts-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdemultimedia1-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdemultimedia1-common-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdemultimedia1-noatun-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdemultimedia1-noatun-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdenetwork2-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdenetwork2-kopete-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-index-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-kaddressbook-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-kitchensync-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-kontact-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-korganizer-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-kpilot-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-ktnef-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdepim2-qopensync-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdesdk1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdesdk1-cervisia-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdesdk1-kbabel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdetoys1-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdetoys1-kweather-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeutils1-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeutils1-common-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeutils1-khexedit-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeutils1-klaptop-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeutils1-kmilo-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdeutils1-ksim-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdevelop-devel-3.5.4-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdevelop3-3.5.4-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdewebdev0-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdewebdev0-kommander-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kjsembed1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kjsembed1-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64smokekde1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64smokeqt1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libarts1-1.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libarts1-devel-1.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfribidi-devel-0.19.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfribidi-static-devel-0.19.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfribidi0-0.19.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgwsoap0-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeaccessibility1-kttsd-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeaccessibility1-kttsd-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdebase4-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdebase4-devel-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdebase4-kate-3.5.10-0.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdecore4-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdecore4-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeedu-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeedu1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegames1-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegames1-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-common-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-common-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kghostview-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kghostview-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kooka-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kooka-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kpovmodeler-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kpovmodeler-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-ksvg-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-ksvg-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kview-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdegraphics0-kview-devel-3.5.10-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdemultimedia1-arts-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdemultimedia1-arts-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdemultimedia1-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdemultimedia1-common-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdemultimedia1-noatun-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdemultimedia1-noatun-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdenetwork2-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdenetwork2-kopete-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-index-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-kaddressbook-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-kitchensync-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-kontact-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-korganizer-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-kpilot-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-ktnef-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdepim2-qopensync-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdesdk1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdesdk1-cervisia-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdesdk1-kbabel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdetoys1-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdetoys1-kweather-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeutils1-common-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeutils1-common-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeutils1-khexedit-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeutils1-klaptop-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeutils1-kmilo-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdeutils1-ksim-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdevelop-devel-3.5.4-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdevelop3-3.5.4-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdewebdev0-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdewebdev0-kommander-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkjsembed1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkjsembed1-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsmokekde1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsmokeqt1-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"lisa-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mandriva-kde-config-common-2008.0-29.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mandriva-kde-translation-2009.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mandriva-kdm-config-2008.0-29.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"nss_mdns-0.10-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"one-kde-config-2008.0-29.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"perl-DCOP-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"powerpack-kde-config-2008.0-29.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-qt-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"smoke-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"task-kde-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"task-kde-devel-3.5.10-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xsettings-kde-0.6-1.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
