#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57619);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id(
    "CVE-2000-0169",
    "CVE-2000-1235",
    "CVE-2000-1236",
    "CVE-2001-0326",
    "CVE-2001-0419",
    "CVE-2001-0591",
    "CVE-2001-1216",
    "CVE-2001-1217",
    "CVE-2001-1371",
    "CVE-2001-1372",
    "CVE-2002-0386",
    "CVE-2002-0559",
    "CVE-2002-0560",
    "CVE-2002-0561",
    "CVE-2002-0562",
    "CVE-2002-0563",
    "CVE-2002-0564",
    "CVE-2002-0565",
    "CVE-2002-0566",
    "CVE-2002-0568",
    "CVE-2002-0569",
    "CVE-2002-0655",
    "CVE-2002-0656",
    "CVE-2002-0659",
    "CVE-2002-0840",
    "CVE-2002-0842",
    "CVE-2002-0843",
    "CVE-2002-0947",
    "CVE-2002-1089",
    "CVE-2002-1630",
    "CVE-2002-1631",
    "CVE-2002-1632",
    "CVE-2002-1635",
    "CVE-2002-1636",
    "CVE-2002-1637",
    "CVE-2002-1858",
    "CVE-2002-2153",
    "CVE-2002-2345",
    "CVE-2002-2347",
    "CVE-2004-1362",
    "CVE-2004-1363",
    "CVE-2004-1364",
    "CVE-2004-1365",
    "CVE-2004-1366",
    "CVE-2004-1367",
    "CVE-2004-1368",
    "CVE-2004-1369",
    "CVE-2004-1370",
    "CVE-2004-1371",
    "CVE-2004-1707",
    "CVE-2004-1774",
    "CVE-2004-1877",
    "CVE-2004-2134",
    "CVE-2004-2244",
    "CVE-2005-1383",
    "CVE-2005-1495",
    "CVE-2005-1496",
    "CVE-2005-2093",
    "CVE-2005-3204",
    "CVE-2005-3445",
    "CVE-2005-3446",
    "CVE-2005-3447",
    "CVE-2005-3448",
    "CVE-2005-3449",
    "CVE-2005-3450",
    "CVE-2005-3451",
    "CVE-2005-3452",
    "CVE-2005-3453",
    "CVE-2006-0273",
    "CVE-2006-0274",
    "CVE-2006-0275",
    "CVE-2006-0282",
    "CVE-2006-0283",
    "CVE-2006-0284",
    "CVE-2006-0285",
    "CVE-2006-0286",
    "CVE-2006-0287",
    "CVE-2006-0288",
    "CVE-2006-0289",
    "CVE-2006-0290",
    "CVE-2006-0291",
    "CVE-2006-0435",
    "CVE-2006-0552",
    "CVE-2006-0586",
    "CVE-2006-1884",
    "CVE-2006-3706",
    "CVE-2006-3707",
    "CVE-2006-3708",
    "CVE-2006-3709",
    "CVE-2006-3710",
    "CVE-2006-3711",
    "CVE-2006-3712",
    "CVE-2006-3713",
    "CVE-2006-3714",
    "CVE-2006-5353",
    "CVE-2006-5354",
    "CVE-2006-5355",
    "CVE-2006-5356",
    "CVE-2006-5357",
    "CVE-2006-5358",
    "CVE-2006-5359",
    "CVE-2006-5360",
    "CVE-2006-5361",
    "CVE-2006-5362",
    "CVE-2006-5363",
    "CVE-2006-5364",
    "CVE-2006-5365",
    "CVE-2006-5366",
    "CVE-2007-0222",
    "CVE-2007-0275",
    "CVE-2007-0280",
    "CVE-2007-0281",
    "CVE-2007-0282",
    "CVE-2007-0283",
    "CVE-2007-0284",
    "CVE-2007-0285",
    "CVE-2007-0286",
    "CVE-2007-0287",
    "CVE-2007-0288",
    "CVE-2007-0289",
    "CVE-2007-1359",
    "CVE-2007-1609",
    "CVE-2007-2119",
    "CVE-2007-2120",
    "CVE-2007-2121",
    "CVE-2007-2122",
    "CVE-2007-2123",
    "CVE-2007-2124",
    "CVE-2007-2130",
    "CVE-2007-3553",
    "CVE-2007-3854",
    "CVE-2007-3859",
    "CVE-2007-3861",
    "CVE-2007-3862",
    "CVE-2007-3863",
    "CVE-2007-5516",
    "CVE-2007-5517",
    "CVE-2007-5518",
    "CVE-2007-5519",
    "CVE-2007-5520",
    "CVE-2007-5521",
    "CVE-2007-5522",
    "CVE-2007-5523",
    "CVE-2007-5524",
    "CVE-2007-5525",
    "CVE-2007-5526",
    "CVE-2007-5531",
    "CVE-2008-0340",
    "CVE-2008-0343",
    "CVE-2008-0344",
    "CVE-2008-0345",
    "CVE-2008-0346",
    "CVE-2008-0347",
    "CVE-2008-0348",
    "CVE-2008-0349",
    "CVE-2008-1812",
    "CVE-2008-1814",
    "CVE-2008-1823",
    "CVE-2008-1824",
    "CVE-2008-1825",
    "CVE-2008-2583",
    "CVE-2008-2588",
    "CVE-2008-2589",
    "CVE-2008-2593",
    "CVE-2008-2594",
    "CVE-2008-2595",
    "CVE-2008-2609",
    "CVE-2008-2612",
    "CVE-2008-2614",
    "CVE-2008-2619",
    "CVE-2008-2623",
    "CVE-2008-3975",
    "CVE-2008-3977",
    "CVE-2008-3986",
    "CVE-2008-3987",
    "CVE-2008-4014",
    "CVE-2008-4017",
    "CVE-2008-5438",
    "CVE-2008-7233",
    "CVE-2009-0217",
    "CVE-2009-0989",
    "CVE-2009-0990",
    "CVE-2009-0994",
    "CVE-2009-1008",
    "CVE-2009-1009",
    "CVE-2009-1010",
    "CVE-2009-1011",
    "CVE-2009-1017",
    "CVE-2009-1976",
    "CVE-2009-1990",
    "CVE-2009-1999",
    "CVE-2009-3407",
    "CVE-2009-3412",
    "CVE-2010-0066",
    "CVE-2010-0067",
    "CVE-2010-0070",
    "CVE-2011-0789",
    "CVE-2011-0795",
    "CVE-2011-0884",
    "CVE-2011-2237",
    "CVE-2011-2314",
    "CVE-2011-3523"
  );

  script_bugtraq_id(
    1053,
    2150,
    2286,
    2569,
    3341,
    3726,
    3727,
    4032,
    4034,
    4037,
    4289,
    4290,
    4292,
    4293,
    4294,
    4298,
    4844,
    4848,
    5119,
    5262,
    5362,
    5363,
    5364,
    5366,
    5452,
    5847,
    5887,
    5902,
    5995,
    5996,
    6556,
    6846,
    7395,
    9515,
    9703,
    10009,
    10829,
    10871,
    13145,
    13418,
    13509,
    15034,
    15134,
    16287,
    16294,
    16384,
    17590,
    19054,
    20588,
    22027,
    22083,
    22831,
    23102,
    23532,
    24697,
    27229,
    33177,
    34461,
    35671,
    35688,
    36746,
    36749,
    36753,
    50202,
    50209
  );

  script_osvdb_id(
    264,
    509,
    705,
    706,
    707,
    711,
    857,
    862,
    1741,
    3411,
    3423,
    3940,
    3941,
    3943,
    4011,
    4553,
    4760,
    5046,
    5406,
    5407,
    5706,
    6695,
    8286,
    9459,
    9464,
    9466,
    9467,
    9468,
    9469,
    9470,
    9471,
    9472,
    9473,
    9474,
    9857,
    9867,
    10885,
    12743,
    12744,
    12745,
    12746,
    12747,
    12748,
    12749,
    12750,
    12752,
    13152,
    14565,
    14895,
    15908,
    16258,
    16862,
    18214,
    18215,
    18216,
    18217,
    18218,
    18219,
    18220,
    18224,
    18760,
    18761,
    20054,
    20187,
    20189,
    20190,
    20615,
    20616,
    20617,
    20618,
    20619,
    20620,
    20621,
    20622,
    20623,
    20624,
    20625,
    20626,
    20627,
    20628,
    22549,
    22568,
    22569,
    22570,
    22571,
    22572,
    22573,
    22574,
    22575,
    22576,
    22577,
    22578,
    22579,
    22580,
    22581,
    22582,
    22583,
    22584,
    22719,
    22839,
    22840,
    24826,
    28877,
    28878,
    28879,
    28880,
    28881,
    28882,
    28883,
    28884,
    28885,
    28886,
    31396,
    31399,
    31400,
    31401,
    31402,
    31403,
    31404,
    31405,
    31406,
    31407,
    31408,
    31409,
    31410,
    31411,
    31412,
    31413,
    32778,
    32879,
    32883,
    32884,
    32894,
    32895,
    32896,
    32897,
    32898,
    32899,
    32900,
    32901,
    32902,
    32903,
    32904,
    32905,
    32906,
    33521,
    37058,
    39937,
    39938,
    39941,
    39942,
    39943,
    39944,
    39945,
    39971,
    39972,
    39973,
    39974,
    39976,
    39991,
    40027,
    40028,
    40029,
    40030,
    40031,
    40032,
    40033,
    40034,
    40035,
    40036,
    40037,
    40039,
    40279,
    40280,
    40281,
    40282,
    40283,
    40293,
    40294,
    40301,
    40303,
    40305,
    40306,
    41689,
    43448,
    44496,
    44497,
    44499,
    44502,
    44508,
    44525,
    44550,
    44551,
    44552,
    44554,
    44590,
    44617,
    47716,
    47717,
    47718,
    47719,
    47720,
    47721,
    47722,
    47723,
    49311,
    49312,
    49313,
    49314,
    49315,
    49316,
    51332,
    51333,
    51334,
    51335,
    53742,
    53743,
    53744,
    53746,
    53747,
    53748,
    53749,
    53750,
    55895,
    55896,
    55907,
    56243,
    59116,
    59117,
    59118,
    59558,
    61730,
    61734,
    61735,
    61736,
    71963,
    71964,
    73969,
    76489,
    76490,
    76491
  );

  script_name(english:"Oracle Application Server Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Oracle Application Server. It was not possible
to determine its version, so the version of Oracle Application Server
installed on the remote host could potentially be affected by multiple
vulnerabilities :

  - CVE-2000-0169: Remote command execution in the web
    listener component.

  - CVE-2000-1235: Information disclosure in the port
    listener component and modplsql.

  - CVE-2000-1236: SQL injection in mod_sql.

  - CVE-2001-0326: Information disclosure in the Java
    Virtual Machine.

  - CVE-2001-0419: Buffer overflow in ndwfn4.so.

  - CVE-2001-0591: Directory traversal.

  - CVE-2001-1216: Buffer overflow in the PL/SQL Apache module.

  - CVE-2001-1217: Directory traversal vulnerability in the
    PL/SQL Apache module.

  - CVE-2001-1371: Improper access control in the SOAP
    service.

  - CVE-2001-1372: Information disclosure.

  - CVE-2002-0386: Denial of service through the
    administration module for Oracle Web Cache.

  - CVE-2002-0559: Buffer overflows in the PL/SQL module.

  - CVE-2002-0560: Information disclosure in the PL/SQL
    module.

  - CVE-2002-0561: Authentication bypass in the PL/SQL
    Gateway web administration interface.

  - CVE-2002-0562: Information disclosure through
    globals.jsa.

  - CVE-2002-0563: Improper access control on several
    services.

  - CVE-2002-0564: Authentication bypass in the PL/SQL
    module.

  - CVE-2002-0565: Information disclosure through JSP files
    in the _pages directory.

  - CVE-2002-0566: Denial of service in the PL/SQL module.

  - CVE-2002-0568: Improper access control on XSQLConfig.xml
    and soapConfig.xml.

  - CVE-2002-0569: Authentication bypass through
    XSQLServlet.

  - CVE-2002-0655: Denial of service in OpenSSL.

  - CVE-2002-0656: Buffer overflows in OpenSSL.

  - CVE-2002-0659: Denial of service in OpenSSL.

  - CVE-2002-0840: Cross-site scripting in the default error
    page of Apache.

  - CVE-2002-0842: Format string vulnerability in mod_dav.

  - CVE-2002-0843: Buffer overflows in ApacheBench.

  - CVE-2002-0947: Buffer overflow in rwcgi60.

  - CVE-2002-1089: Information disclosure in rwcgi60.

  - CVE-2002-1630: Improper access control on sendmail.jsp.

  - CVE-2002-1631: SQL injection in query.xsql.

  - CVE-2002-1632: Information disclosure through several
    JSP pages.

  - CVE-2002-1635: Information disclosure in Apache.

  - CVE-2002-1636: Cross-site scripting in the htp PL/SQL
    package.

  - CVE-2002-1637: Default credentials in multiple
    components.

  - CVE-2002-1858: Information disclosure through the
    WEB-INF directory.

  - CVE-2002-2153: Format string vulnerability in the
    administrative pages of the PL/SQL module.

  - CVE-2002-2345: Credential leakage in the web cache
    administrator interface.

  - CVE-2002-2347: Cross-site scripting in several JSP
    pages.

  - CVE-2004-1362: Authentication bypass in the PL/SQL
    module.

  - CVE-2004-1363: Buffer overflow in extproc.

  - CVE-2004-1364: Directory traversal in extproc.

  - CVE-2004-1365: Command execution in extproc.

  - CVE-2004-1366: Improper access control on
    emoms.properties.

  - CVE-2004-1367: Credential leakage in Database Server.

  - CVE-2004-1368: Arbitrary file execution in ISQL*Plus.

  - CVE-2004-1369: Denial of service in TNS Listener.

  - CVE-2004-1370: Multiple SQL injection vulnerabilities in
    PL/SQL.

  - CVE-2004-1371: Stack-based buffer overflow.

  - CVE-2004-1707: Privilege escalation in dbsnmp and nmo.

  - CVE-2004-1774: Buffer overflow in the MD2 package.

  - CVE-2004-1877: Phishing vulnerability in Single Sign-On
    component.

  - CVE-2004-2134: Weak cryptography for passwords in the
    toplink mapping workBench.

  - CVE-2004-2244: Denial of service in the XML parser.

  - CVE-2005-1383: Authentication bypass in HTTP Server.

  - CVE-2005-1495: Detection bypass.

  - CVE-2005-1496: Privilege escalation in the
    DBMS_Scheduler.

  - CVE-2005-2093: Web cache poisoning.

  - CVE-2005-3204: Cross-site scripting.

  - CVE-2005-3445: Multiple unspecified vulnerabilities in
    HTTP Server.

  - CVE-2005-3446: Unspecified vulnerability in Internet
    Directory.

  - CVE-2005-3447: Unspecified vulnerability in Single
    Sign-On.

  - CVE-2005-3448: Unspecified vulnerability in the OC4J
    module.

  - CVE-2005-3449: Multiple unspecified vulnerabilities in
    multiple components.

  - CVE-2005-3450: Unspecified vulnerability in HTTP Server.

  - CVE-2005-3451: Unspecified vulnerability in
    SQL*ReportWriter.

  - CVE-2005-3452: Unspecified vulnerability in Web Cache.

  - CVE-2005-3453: Multiple unspecified vulnerabilities in
    Web Cache.

  - CVE-2006-0273: Unspecified vulnerability in the Portal
    component.

  - CVE-2006-0274: Unspecified vulnerability in the Oracle
    Reports Developer component.

  - CVE-2006-0275: Unspecified vulnerability in the Oracle
    Reports Developer component.

  - CVE-2006-0282: Unspecified vulnerability.

  - CVE-2006-0283: Unspecified vulnerability.

  - CVE-2006-0284: Multiple unspecified vulnerabilities.

  - CVE-2006-0285: Unspecified vulnerability in the Java Net
    component.

  - CVE-2006-0286: Unspecified vulnerability in HTTP Server.

  - CVE-2006-0287: Unspecified vulnerability in HTTP Server.

  - CVE-2006-0288: Multiple unspecified vulnerabilities in
    the Oracle Reports Developer component.

  - CVE-2006-0289: Multiple unspecified vulnerabilities.

  - CVE-2006-0290: Unspecified vulnerability in the Oracle
    Workflow Cartridge component.

  - CVE-2006-0291: Multiple unspecified vulnerabilities in
    the Oracle Workflow Cartridge component.

  - CVE-2006-0435: Unspecified vulnerability in Oracle
    PL/SQL.

  - CVE-2006-0552: Unspecified vulnerability in the Net
    Listener component.

  - CVE-2006-0586: Multiple SQL injection vulnerabilities.

  - CVE-2006-1884: Unspecified vulnerability in the Oracle
    Thesaurus Management System component.

  - CVE-2006-3706: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3707: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3708: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3709: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3710: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3711: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3712: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3713: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-3714: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-5353: Unspecified vulnerability in HTTP Server.

  - CVE-2006-5354: Unspecified vulnerability in HTTP Server.

  - CVE-2006-5355: Unspecified vulnerability in Single
    Sign-On.

  - CVE-2006-5356: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-5357: Unspecified vulnerability in HTTP Server.

  - CVE-2006-5358: Unspecified vulnerability in the Oracle
    Forms component.

  - CVE-2006-5359: Multiple unspecified vulnerabilities in
    Oracle Reports Developer component.

  - CVE-2006-5360: Unspecified vulnerability in Oracle Forms
    component.

  - CVE-2006-5361: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-5362: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-5363: Unspecified vulnerability in Single
    Sign-On.

  - CVE-2006-5364: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2006-5365: Unspecified vulnerability in Oracle
    Forms.

  - CVE-2006-5366: Multiple unspecified vulnerabilities.

  - CVE-2007-0222: Directory traversal vulnerability in
    EmChartBean.

  - CVE-2007-0275: Cross-site scripting vulnerability in
    Oracle Reports Web Cartridge (RWCGI60).

  - CVE-2007-0280: Buffer overflow in Oracle Notification
    Service.

  - CVE-2007-0281: Multiple unspecified vulnerabilities in
    HTTP Server.

  - CVE-2007-0282: Unspecified vulnerability in OPMN02.

  - CVE-2007-0283: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2007-0284: Multiple unspecified vulnerabilities in
    Oracle Containers for J2EE.

  - CVE-2007-0285: Unspecified vulnerability in Oracle
    Reports Developer.

  - CVE-2007-0286: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2007-0287: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2007-0288: Unspecified vulnerability in Oracle
    Internet Directory.

  - CVE-2007-0289: Multiple unspecified vulnerabilities in
    Oracle Containers for J2EE.

  - CVE-2007-1359: Improper access control in mod_security.

  - CVE-2007-1609: Cross-site scripting vulnerability in
    servlet/Spy in Dynamic Monitoring Services (DMS).

  - CVE-2007-2119: Cross-site scripting vulnerability in the
    Administration Front End for Oracle Enterprise (Ultra)
    Search.

  - CVE-2007-2120: Denial of service in the Oracle
    Discoverer servlet.

  - CVE-2007-2121: Unspecified vulnerability in the COREid
    Access component.

  - CVE-2007-2122: Unspecified vulnerability in the Wireless
    component.

  - CVE-2007-2123: Unspecified vulnerability in the Portal
    component.

  - CVE-2007-2124: Unspecified vulnerability in the Portal
    component.

  - CVE-2007-2130: Unspecified vulnerability in Workflow
    Cartridge.

  - CVE-2007-3553: Cross-site scripting vulnerability in
    Rapid Install Web Server.

  - CVE-2007-3854: Multiple unspecified vulnerabilities in
    the Advanced Queuing component and the Spatial
    component.

  - CVE-2007-3859: Unspecified vulnerability in the Oracle
    Internet Directory component.

  - CVE-2007-3861: Unspecified vulnerability in Oracle
    Jdeveloper.

  - CVE-2007-3862: Unspecified vulnerability in Single
    Sign-On.

  - CVE-2007-3863: Unspecified vulnerability in Oracle
    JDeveloper.

  - CVE-2007-5516: Unspecified vulnerability in the Oracle
    Process Mgmt & Notification component.

  - CVE-2007-5517: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2007-5518: Unspecified vulnerability in HTTP Server.

  - CVE-2007-5519: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2007-5520: Unspecified vulnerability in the Oracle
    Internet Directory component.

  - CVE-2007-5521: Unspecified vulnerability in Oracle
    Containers for J2EE.

  - CVE-2007-5522: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2007-5523: Unspecified vulnerability in the Oracle
    Internet Directory component.

  - CVE-2007-5524: Unspecified vulnerability in Single
    Sign-On.

  - CVE-2007-5525: Unspecified vulnerability in Single
    Sign-On.

  - CVE-2007-5526: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2007-5531: Unspecified vulnerability in Oracle Help
    for Web.

  - CVE-2008-0340: Multiple unspecified vulnerabilities in
    the Advanced Queuing component and Spatial component.

  - CVE-2008-0343: Unspecified vulnerability in the Oracle
    Spatial component.

  - CVE-2008-0344: Unspecified vulnerability in the Oracle
    Spatial component.

  - CVE-2008-0345: Unspecified vulnerability in the Core
    RDBMS component.

  - CVE-2008-0346: Unspecified vulnerability in the Oracle
    Jinitiator component.

  - CVE-2008-0347: Unspecified vulnerability in the Oracle
    Ultra Search component.

  - CVE-2008-0348: Multiple unspecified vulnerabilities in
    the PeopleTools component.

  - CVE-2008-0349: Unspecified vulnerability in the
    PeopleTools component.

  - CVE-2008-1812: Unspecified vulnerability in the Oracle
    Enterprise Manager component.

  - CVE-2008-1814: Unspecified vulnerability in the Oracle
    Secure Enterprise Search or Ultrasearch component.

  - CVE-2008-1823: Unspecified vulnerability in the Oracle
    Jinitiator component.

  - CVE-2008-1824: Unspecified vulnerability in the Oracle
    Dynamic Monitoring Service component.

  - CVE-2008-1825: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-2583: Unspecified vulnerability in the sample
    Discussion Forum Portlet for the Oracle Portal
    component.

  - CVE-2008-2588: Unspecified vulnerability in the Oracle
    JDeveloper component.

  - CVE-2008-2589: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-2593: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-2594: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-2595: Unspecified vulnerability in the Oracle
    Internet Directory component.

  - CVE-2008-2609: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-2612: Unspecified vulnerability in the Hyperion
    BI Plus component.

  - CVE-2008-2614: Unspecified vulnerability in HTTP Server.

  - CVE-2008-2619: Unspecified vulnerability in the Oracle
    Reports Developer component.

  - CVE-2008-2623: Unspecified vulnerability in the Oracle
    JDeveloper component.

  - CVE-2008-3975: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-3977: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-3986: Unspecified vulnerability in the Oracle
    Discoverer Administrator component.

  - CVE-2008-3987: Unspecified vulnerability in the Oracle
    Discoverer Desktop component.

  - CVE-2008-4014: Unspecified vulnerability in the Oracle
    BPEL Process Manager component.

  - CVE-2008-4017: Unspecified vulnerability in the OC4J
    component.

  - CVE-2008-5438: Unspecified vulnerability in the Oracle
    Portal component.

  - CVE-2008-7233: Unspecified vulnerability in the Oracle
    Jinitiator component.

  - CVE-2009-0217: Signature spoofing vulnerability in
    multiple components.

  - CVE-2009-0989: Unspecified vulnerability in the BI
    Publisher component.

  - CVE-2009-0990: Unspecified vulnerability in the BI
    Publisher component.

  - CVE-2009-0994: Unspecified vulnerability in the BI
    Publisher component.

  - CVE-2009-1008: Unspecified vulnerability in the Outside
    In Technology component.

  - CVE-2009-1009: Unspecified vulnerability in the Outside
    In Technology component.

  - CVE-2009-1010: Unspecified vulnerability in the Outside
    In Technology component.

  - CVE-2009-1011: Unspecified vulnerability in the Outside
    In Technology component.

  - CVE-2009-1017: Unspecified vulnerability in the BI
    Publisher component.

  - CVE-2009-1976: Unspecified vulnerability in HTTP Server.

  - CVE-2009-1990: Unspecified vulnerability in the Business
    Intelligence Enterprise Edition component.

  - CVE-2009-1999: Unspecified vulnerability in the Business
    Intelligence Enterprise Edition component.

  - CVE-2009-3407: Unspecified vulnerability in the Portal
    component.

  - CVE-2009-3412: Unspecified vulnerability in the Unzip
    component.

  - CVE-2010-0066: Unspecified vulnerability in the Access
    Manager Identity Server component.

  - CVE-2010-0067: Unspecified vulnerability in the Oracle
    Containers for J2EE component.

  - CVE-2010-0070: Unspecified vulnerability in the Oracle
    Containers for J2EE component.

  - CVE-2011-0789: Unspecified vulnerability in HTTP Server.

  - CVE-2011-0795: Unspecified vulnerability in Single
    Sign-On.

  - CVE-2011-0884: Unspecified vulnerability in the Oracle
    BPEL Process Manager component.

  - CVE-2011-2237: Unspecified vulnerability in the Oracle
    Web Services Manager component.

  - CVE-2011-2314: Unspecified vulnerability in the Oracle
    Containers for J2EE component.

  - CVE-2011-3523: Unspecified vulnerability in the Oracle
    Web Services Manager component.");
  script_set_attribute(attribute:"solution", value:
"Verify that the version of Oracle Application Server installed is not
affected by the listed vulnerabilities and/or filter incoming traffic to this port");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-053");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Oracle Secure Backup 10.2.0.2 RCE (Windows)");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 79, 119, 200, 255, 264, 287);
script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/oracle_application_server");

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Make sure this is Oracle.
port = get_kb_item_or_exit("Services/oracle_application_server");

# We're flagging every installation of Oracle Application Server, with
# every vulnerability it has ever had.
security_hole(port);
