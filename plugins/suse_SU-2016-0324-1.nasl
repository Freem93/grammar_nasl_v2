#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0324-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88575);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2014-8146", "CVE-2014-8147", "CVE-2014-9093", "CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");
  script_bugtraq_id(71313, 74457);
  script_osvdb_id(121624, 121625, 129856, 129857, 129858, 129859);

  script_name(english:"SUSE SLED11 Security Update : Recommended update for LibreOffice (SUSE-SU-2016:0324-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings LibreOffice to version 5.0.4, a major version
update.

It brings lots of new features, bug fixes and also security fixes.

Features as seen on http://www.libreoffice.org/discover/new-features/

  - LibreOffice 5.0 ships an impressive number of new
    features for its spreadsheet module, Calc: complex
    formulae image cropping, new functions, more powerful
    conditional formatting, table addressing and much more.
    Calc's blend of performance and features makes it an
    enterprise-ready, heavy duty spreadsheet application
    capable of handling all kinds of workload for an
    impressive range of use cases

  - New icons, major improvements to menus and sidebar : no
    other LibreOffice version has looked that good and
    helped you be creative and get things done the right
    way. In addition, style management is now more intuitive
    thanks to the visualization of styles right in the
    interface.

  - LibreOffice 5 ships with numerous improvements to
    document import and export filters for MS Office, PDF,
    RTF, and more. You can now timestamp PDF documents
    generated with LibreOffice and enjoy enhanced document
    conversion fidelity all around.

The Pentaho Flow Reporting Engine is now added and used.

Security issues fixed :

  - CVE-2014-8146: The resolveImplicitLevels function in
    common/ubidi.c in the Unicode Bidirectional Algorithm
    implementation in ICU4C in International Components for
    Unicode (ICU) before 55.1 did not properly track
    directionally isolated pieces of text, which allowed
    remote attackers to cause a denial of service
    (heap-based buffer overflow) or possibly execute
    arbitrary code via crafted text.

  - CVE-2014-8147: The resolveImplicitLevels function in
    common/ubidi.c in the Unicode Bidirectional Algorithm
    implementation in ICU4C in International Components for
    Unicode (ICU) before 55.1 used an integer data type that
    is inconsistent with a header file, which allowed remote
    attackers to cause a denial of service (incorrect malloc
    followed by invalid free) or possibly execute arbitrary
    code via crafted text.

  - CVE-2015-4551: An arbitrary file disclosure
    vulnerability in Libreoffice and Openoffice Calc and
    Writer was fixed.

  - CVE-2015-5212: A LibreOffice 'PrinterSetup Length'
    integer underflow vulnerability could be used by
    attackers supplying documents to execute code as the
    user opening the document.

  - CVE-2015-5213: A LibreOffice 'Piece Table Counter'
    invalid check design error vulnerability allowed
    attackers supplying documents to execute code as the
    user opening the document.

  - CVE-2015-5214: Multiple Vendor LibreOffice Bookmark
    Status Memory Corruption Vulnerability allowed attackers
    supplying documents to execute code as the user opening
    the document.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.libreoffice.org/discover/new-features/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/306333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/547549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/668145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/679938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/681560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/688200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/718113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/806250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/857026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/889755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/890735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5214.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160324-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cb3ddc7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-libreoffice-504-1174=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-libreoffice-504-1174=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-libreoffice-504-1174=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhyphen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmythes-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-voikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvoikko1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-af_NA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_AE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_BH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_DZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_EG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_IQ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_JO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_KW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_LB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_LY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_MA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_OM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_QA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_SA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_SD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_SY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_TN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ar_YE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-be_BY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-bn_BD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-bn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-bs_BA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ca_AD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ca_ES_valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ca_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ca_IT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-de_AT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-de_CH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-de_DE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_AU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_BS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_BZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_CA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_GH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_JM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_MW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_NA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_NZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_PH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_TT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-en_ZW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_BO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_CL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_CO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_CR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_CU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_DO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_EC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_GT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_HN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_MX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_NI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_PA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_PE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_PR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_PY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_SV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_UY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-es_VE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-fr_BE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-fr_CA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-fr_CH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-fr_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-fr_LU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-fr_MC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-it_IT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lo_LA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lv_LV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-nl_BE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-nl_NL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-pt_AO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ro_RO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sr_Latn_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sr_Latn_RS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sr_RS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sv_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-vi_VN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-importlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libhyphen0-2.8.8-2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libmythes-1_2-0-1.2.4-2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-base-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-extensions-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-draw-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-filters-optional-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-gnome-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-icon-theme-galaxy-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-icon-theme-tango-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-impress-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-kde4-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-af-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-ar-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-ca-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-cs-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-da-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-de-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-en-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-es-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-fi-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-fr-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-gu-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-hi-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-hu-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-it-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-ja-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-ko-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-nb-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-nl-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-nn-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-pl-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-pt-BR-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-pt-PT-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-ru-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-sk-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-sv-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-xh-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-zh-Hans-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-zh-Hant-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-l10n-zu-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-mailmerge-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-math-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-officebean-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-pyuno-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-sdk-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-voikko-4.1-2.26")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-extensions-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libvoikko1-3.7.1-5.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-af_NA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-af_ZA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_AE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_BH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_DZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_EG-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_IQ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_JO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_KW-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_LB-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_LY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_MA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_OM-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_QA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_SA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_SD-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_SY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_TN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ar_YE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-be_BY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-bg_BG-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-bn_BD-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-bn_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-bs-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-bs_BA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ca-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ca_AD-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ca_ES-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ca_ES_valencia-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ca_FR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ca_IT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-cs_CZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-da_DK-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-de-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-de_AT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-de_CH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-de_DE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-dictionaries-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-el_GR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_AU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_BS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_BZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_CA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_GB-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_GH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_IE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_JM-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_MW-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_NA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_NZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_PH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_TT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_US-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_ZA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-en_ZW-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_AR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_BO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_CL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_CO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_CR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_CU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_DO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_EC-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_ES-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_GT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_HN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_MX-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_NI-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_PA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_PE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_PR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_PY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_SV-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_UY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-es_VE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-et_EE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-fr_BE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-fr_CA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-fr_CH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-fr_FR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-fr_LU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-fr_MC-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-gu_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-he_IL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-hi_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-hr_HR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-hu_HU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-it_IT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-en-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-hu_HU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-pt_BR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-lightproof-ru_RU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-lo_LA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-lt_LT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-lv_LV-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-nb_NO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-nl_BE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-nl_NL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-nn_NO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-no-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-pl_PL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-pt_AO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-pt_BR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-pt_PT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ro-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ro_RO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-ru_RU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sk_SK-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sl_SI-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sr-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sr_CS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sr_Latn_CS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sr_Latn_RS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sr_RS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sv_FI-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-sv_SE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-te-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-te_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-th_TH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-vi-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-vi_VN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"myspell-zu_ZA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"python-importlib-1.0.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libhyphen0-2.8.8-2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libmythes-1_2-0-1.2.4-2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-base-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-base-drivers-postgresql-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-calc-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-calc-extensions-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-draw-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-filters-optional-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-gnome-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-icon-theme-galaxy-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-icon-theme-tango-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-impress-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-kde4-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-af-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-ar-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-ca-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-cs-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-da-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-de-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-en-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-es-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-fi-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-fr-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-gu-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-hi-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-hu-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-it-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-ja-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-ko-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-nb-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-nl-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-nn-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-pl-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-pt-BR-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-pt-PT-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-ru-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-sk-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-sv-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-xh-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-zh-Hans-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-zh-Hant-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-l10n-zu-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-mailmerge-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-math-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-officebean-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-pyuno-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-sdk-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-voikko-4.1-2.26")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-writer-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libreoffice-writer-extensions-5.0.4.2-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libvoikko1-3.7.1-5.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-af_NA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-af_ZA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_AE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_BH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_DZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_EG-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_IQ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_JO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_KW-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_LB-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_LY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_MA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_OM-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_QA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_SA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_SD-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_SY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_TN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ar_YE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-be_BY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-bg_BG-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-bn_BD-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-bn_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-bs-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-bs_BA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ca-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ca_AD-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ca_ES-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ca_ES_valencia-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ca_FR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ca_IT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-cs_CZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-da_DK-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-de-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-de_AT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-de_CH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-de_DE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-dictionaries-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-el_GR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_AU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_BS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_BZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_CA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_GB-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_GH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_IE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_JM-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_MW-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_NA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_NZ-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_PH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_TT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_US-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_ZA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-en_ZW-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_AR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_BO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_CL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_CO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_CR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_CU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_DO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_EC-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_ES-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_GT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_HN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_MX-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_NI-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_PA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_PE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_PR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_PY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_SV-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_UY-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-es_VE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-et_EE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-fr_BE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-fr_CA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-fr_CH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-fr_FR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-fr_LU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-fr_MC-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-gu_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-he_IL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-hi_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-hr_HR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-hu_HU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-it_IT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-lightproof-en-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-lightproof-hu_HU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-lightproof-pt_BR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-lightproof-ru_RU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-lo_LA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-lt_LT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-lv_LV-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-nb_NO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-nl_BE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-nl_NL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-nn_NO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-no-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-pl_PL-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-pt_AO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-pt_BR-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-pt_PT-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ro-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ro_RO-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-ru_RU-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sk_SK-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sl_SI-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sr-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sr_CS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sr_Latn_CS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sr_Latn_RS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sr_RS-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sv_FI-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-sv_SE-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-te-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-te_IN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-th_TH-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-vi-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-vi_VN-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"myspell-zu_ZA-20150827-23.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"python-importlib-1.0.2-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Recommended update for LibreOffice");
}
