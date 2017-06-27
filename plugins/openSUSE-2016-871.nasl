#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-871.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92310);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-0794", "CVE-2016-0795");

  script_name(english:"openSUSE Security Update : LibreOffice (openSUSE-2016-871)");
  script_summary(english:"Check for the openSUSE-2016-871 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to version 5.1.3.2, bringing many new features
and bug fixes.

Two security issues have been fixed :

  - CVE-2016-0795: LibreOffice allowed remote attackers to
    cause a denial of service (memory corruption) or
    possibly have unspecified other impact via a crafted
    LwpTocSuperLayout record in a LotusWordPro (lwp)
    document.

  - CVE-2016-0794: The lwp filter in LibreOffice allowed
    remote attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via a crafted LotusWordPro (lwp) document.

A comprehensive list of new features and improvements in this release
is provided by the Document Foundation at
https://wiki.documentfoundation.org/ReleaseNotes/5.1 .

This update was imported from the SUSE:SLE-12:Update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=718113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=856729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/320521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/5.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected LibreOffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cmis-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cmis-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cmis-client-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hyphen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hyphen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hyphen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-0_5-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-0_5-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-c-0_5-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-c-0_5-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-0_1-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetonyek-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhyphen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhyphen0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhyphen0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhyphen0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-0_11-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-0_11-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libixion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-0_11-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-0_11-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liborcus-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gdb-pretty-printers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisio-0_1-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisio-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisio-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvisio-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-0_4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwps-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mdds-1_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-af_NA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-an_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_AE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_BH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_DZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_EG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_IQ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_JO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_KW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_LB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_LY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_MA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_OM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_QA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_SA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_SD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_SY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_TN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ar_YE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-be_BY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bn_BD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-br_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-bs_BA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_AD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_ES_valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ca_IT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de_AT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de_CH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-de_DE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_AU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_BS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_BZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_CA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_GH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_JM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_MW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_NA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_NZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_PH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_TT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-en_ZW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_BO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_CU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_DO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_EC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_GT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_HN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_MX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_NI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_PY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_SV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_UY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-es_VE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_BE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_CA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_CH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_LU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-fr_MC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gd_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-gug_PY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-is_IS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-it_IT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kmr_Latn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kmr_Latn_SY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-kmr_Latn_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lo_LA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-lv_LV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ne_NP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nl_BE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nl_NL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-oc_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pt_AO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ro_RO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-si_LK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_Latn_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_Latn_RS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sr_RS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sv_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-sw_TZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-uk_UA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-vi_VN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:myspell-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"cmis-client-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cmis-client-debuginfo-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cmis-client-debugsource-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hunspell-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hunspell-debuginfo-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hunspell-debugsource-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hunspell-devel-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hunspell-static-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hunspell-tools-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hunspell-tools-debuginfo-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hyphen-2.8.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hyphen-debugsource-2.8.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hyphen-devel-2.8.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcmis-0_5-5-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcmis-0_5-5-debuginfo-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcmis-c-0_5-5-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcmis-c-0_5-5-debuginfo-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcmis-c-devel-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcmis-devel-0.5.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libetonyek-0_1-1-0.1.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libetonyek-0_1-1-debuginfo-0.1.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libetonyek-debugsource-0.1.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libetonyek-devel-0.1.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libetonyek-tools-0.1.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libetonyek-tools-debuginfo-0.1.6-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libhyphen0-2.8.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libhyphen0-debuginfo-2.8.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-0_11-0-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-0_11-0-debuginfo-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-debugsource-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-devel-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-python3-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-python3-debuginfo-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-tools-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libixion-tools-debuginfo-0.11.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-0_11-0-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-0_11-0-debuginfo-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-debugsource-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-devel-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-python3-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-python3-debuginfo-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-tools-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liborcus-tools-debuginfo-0.11.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-mysql-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-mysql-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-postgresql-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-branding-upstream-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-calc-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-calc-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-calc-extensions-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-debugsource-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-draw-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-draw-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-filters-optional-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gdb-pretty-printers-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-glade-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gnome-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gnome-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gtk3-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gtk3-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-breeze-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-galaxy-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-hicontrast-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-oxygen-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-sifr-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-tango-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-impress-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-impress-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-kde4-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-kde4-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-af-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ar-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-as-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-bg-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-bn-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-br-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ca-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-cs-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-cy-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-da-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-de-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-dz-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-el-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-en-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-es-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-et-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-eu-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-fa-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-fi-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-fr-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ga-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-gl-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-gu-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-he-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-hi-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-hr-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-hu-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-it-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ja-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-kk-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-kn-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ko-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-lt-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-lv-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-mai-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ml-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-mr-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nb-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nl-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nn-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nr-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nso-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-or-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pa-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pl-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pt-BR-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pt-PT-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ro-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ru-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-si-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sk-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sl-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sr-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ss-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-st-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sv-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ta-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-te-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-th-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-tn-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-tr-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ts-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-uk-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ve-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-xh-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-zh-Hans-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-zh-Hant-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-zu-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-mailmerge-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-math-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-math-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-officebean-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-officebean-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-pyuno-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-pyuno-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-sdk-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-sdk-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-writer-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-writer-debuginfo-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-writer-extensions-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreofficekit-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreofficekit-devel-5.1.3.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvisio-0_1-1-0.1.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvisio-0_1-1-debuginfo-0.1.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvisio-debugsource-0.1.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvisio-devel-0.1.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvisio-tools-0.1.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvisio-tools-debuginfo-0.1.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwps-0_4-4-0.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwps-0_4-4-debuginfo-0.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwps-debugsource-0.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwps-devel-0.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwps-tools-0.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwps-tools-debuginfo-0.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mdds-1_0-devel-1.1.0-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-af_NA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-af_ZA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-an-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-an_ES-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_AE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_BH-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_DZ-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_EG-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_IQ-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_JO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_KW-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_LB-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_LY-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_MA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_OM-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_QA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_SA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_SD-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_SY-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_TN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ar_YE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-be_BY-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-bg_BG-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-bn_BD-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-bn_IN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-br_FR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-bs-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-bs_BA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ca-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ca_AD-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ca_ES-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ca_ES_valencia-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ca_FR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ca_IT-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-cs_CZ-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-da_DK-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-de-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-de_AT-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-de_CH-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-de_DE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-dictionaries-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-el_GR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_AU-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_BS-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_BZ-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_CA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_GB-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_GH-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_IE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_IN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_JM-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_MW-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_NA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_NZ-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_PH-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_TT-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_US-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_ZA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-en_ZW-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_AR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_BO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_CL-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_CO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_CR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_CU-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_DO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_EC-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_ES-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_GT-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_HN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_MX-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_NI-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_PA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_PE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_PR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_PY-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_SV-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_UY-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-es_VE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-et_EE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-fr_BE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-fr_CA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-fr_CH-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-fr_FR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-fr_LU-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-fr_MC-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-gd_GB-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-gl-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-gl_ES-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-gu_IN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-gug-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-gug_PY-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-he_IL-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-hi_IN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-hr_HR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-hu_HU-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-is-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-is_IS-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-it_IT-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-kmr_Latn-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-kmr_Latn_SY-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-kmr_Latn_TR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-lightproof-en-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-lightproof-hu_HU-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-lightproof-pt_BR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-lightproof-ru_RU-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-lo_LA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-lt_LT-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-lv_LV-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-nb_NO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ne_NP-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-nl_BE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-nl_NL-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-nn_NO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-no-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-oc_FR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-pl_PL-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-pt_AO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-pt_BR-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-pt_PT-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ro-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ro_RO-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-ru_RU-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-si_LK-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sk_SK-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sl_SI-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sr-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sr_CS-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sr_Latn_CS-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sr_Latn_RS-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sr_RS-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sv_FI-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sv_SE-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-sw_TZ-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-te-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-te_IN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-th_TH-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-uk_UA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-vi-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-vi_VN-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"myspell-zu_ZA-20160511-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"hunspell-32bit-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"hunspell-debuginfo-32bit-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"hunspell-devel-32bit-1.3.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libhyphen0-32bit-2.8.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libhyphen0-debuginfo-32bit-2.8.8-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cmis-client / cmis-client-debuginfo / cmis-client-debugsource / etc");
}
