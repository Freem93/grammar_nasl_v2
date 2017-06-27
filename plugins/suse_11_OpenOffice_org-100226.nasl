#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45064);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302", "CVE-2010-0136");

  script_name(english:"SuSE 11 Security Update : OpenOffice_org (SAT Patch Number 2080)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of OpenOffice_org includes fixes for the following
vulnerabilities :

  - XML signature weakness. (CVE-2009-0217)

  - XPM Import Integer Overflow. (CVE-2009-2949)

  - GIF Import Heap Overflow. (CVE-2009-2950)

  - MS Word sprmTDefTable Memory Corruption. (CVE-2009-3301)

  - MS Word sprmTDefTable Memory Corruption. (CVE-2009-3302)

  - In the ooo-build variant of OpenOffice_org VBA Macro
    support does not honor Macro security settings.
    (CVE-2010-0136)

This also provides the maintenance update to OpenOffice.org-3.2.

Details about all upstream changes can be found at
http://development.openoffice.org/releases/3.2.0.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=232232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=370015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=417818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=438606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=464436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=464568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=473232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=481242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=485637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=504623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=515972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=519715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=521564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=537541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=537931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=538559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=539220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=539282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=539434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=540225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=540563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=540566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=540726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=540923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=540960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=542024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=542123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=542132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=542684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=542854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=544166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=545287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=545717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=545815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=546416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=546421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=546758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=549300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=549331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=549383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=549728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=551402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=553219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=553819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=555889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=558505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=558564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=558577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=558907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=559393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=559438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=559445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=560255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=560355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=560877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=561639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=565184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=566030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=566581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=568016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=568146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=568399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=571489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=572372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=577873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=581634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2949.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3301.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3302.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0136.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2080.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-LanguageTool-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-components");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-en-US-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-libs-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-libs-extern");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-libs-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-openclipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-de-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-en-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-es-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-fr-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-it-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-nl-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-pl-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-LanguageTool-sv-1.0.0-1.1.6")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-base-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-base-drivers-postgresql-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-base-extensions-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-calc-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-calc-extensions-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-components-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-draw-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-draw-extensions-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-filters-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-filters-optional-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-gnome-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ar-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-cs-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-da-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-de-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-en-GB-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-en-US-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-en-US-devel-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-es-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-fr-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-gu-IN-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-hi-IN-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-hu-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-it-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ja-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ko-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-nl-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-pl-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-pt-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-pt-BR-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ru-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-sv-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-zh-CN-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-zh-TW-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-icon-themes-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-impress-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-impress-extensions-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-kde-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-af-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ar-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ca-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-cs-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-da-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-de-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-el-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-en-GB-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-es-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-extras-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-fi-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-fr-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-gu-IN-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-hi-IN-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-hu-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-it-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ja-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ko-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-nb-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-nl-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-nn-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-pl-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-pt-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-pt-BR-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ru-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-sk-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-sv-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-xh-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-zh-CN-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-zh-TW-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-zu-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-libs-core-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-libs-extern-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-libs-gui-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-mailmerge-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-math-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-mono-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-officebean-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-openclipart-3-1.25.5")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-pyuno-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-ure-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-writer-3.2.0.7-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-writer-extensions-3.2.0.7-0.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
