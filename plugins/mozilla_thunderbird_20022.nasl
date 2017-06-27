#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39493);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id(
    "CVE-2009-1302", 
    "CVE-2009-1303",
    "CVE-2009-1304", 
    "CVE-2009-1305",
    "CVE-2009-1307", 
    "CVE-2009-1392", 
    "CVE-2009-1832", 
    "CVE-2009-1833",
    "CVE-2009-1836", 
    "CVE-2009-1838", 
    "CVE-2009-1841", 
    "CVE-2009-2210"
  );
  script_bugtraq_id(35370, 35371, 35372, 35373, 35380, 35383, 35461);
  script_osvdb_id(
    53958,
    53960,
    53961,
    53962,
    53963,
    53964,
    53965,
    53966,
    53967,
    53969,
    53970,
    53971,
    53972,
    55138,
    55139,
    55140,
    55141,
    55142,
    55143,
    55144,
    55145,
    55146,
    55147,
    55148,
    55152,
    55153,
    55154,
    55155,
    55157,
    55159,
    55160,
    55532
  );
  script_xref(name:"Secunia", value:"35440");
  script_xref(name:"OSVDB", value:"55138"); # 55138 - 55147 abstract for each Browser Engine flaw
  script_xref(name:"OSVDB", value:"55152"); # 55152 - 55155 abstract for each JavaScript Engine flaw

  script_name(english:"Mozilla Thunderbird < 2.0.0.22 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities." );

  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 2.0.0.22.  Such
versions are potentially affected by the following security issues :

  - Multiple memory corruption vulnerabilities could
    potentially be exploited to execute arbitrary code
    provided JavaScript is enabled in mail. 
    (MFSA 2009-14)

  - When an Adobe Flash file is loaded via the
    'view-source:' scheme, the Flash plugin misinterprets
    the origin of the content as localhost. An attacker can
    leverage this to launch cross-site request forgery
    attacks. It is also possible to exploit this to place
    cookie-like objects on victim's computers.
    (MFSA 2009-17)

  - Multiple memory corruption vulnerabilities could
    potentially be exploited to execute arbitrary code.
    (MFSA 2009-24)

  - It may be possible to tamper with SSL data via non-200
    responses to proxy CONNECT requests. (MFSA 2009-27)

  - If the owner document of an element becomes null after
    garbage collection, then it may be possible to execute
    the event listeners within the wrong JavaScript context.
    An attacker can potentially exploit this vulnerability
    to execute arbitrary JavaScript with chrome privileges,
    provided JavaScript is enabled in mail. (MFSA 2009-29)

  - It may be possible for scripts from page content to
    run with elevated privileges. Thunderbird installs are
    not affected by default, however if an add-on is 
    installed that implements functionality similar to 
    sidebar or BrowserFeedWriter, and also enables
    JavaScript then the install could be vulnerable.
    (MFSA 2009-32)

  - It may be possible to crash Thunderbird while viewing a
    'multipart/alternative' mail message with a 
    'text/enhanced' part. (MFSA 2009-33)" );

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-14.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-17.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-24.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-27.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-29.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-32.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-33.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird 2.0.0.22 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 94, 287, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/23");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/04/21");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.22', severity:SECURITY_HOLE);